#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include <set>

#define LED_PIN 33

std::set<String> seenHandshakes;
File handshakeFile;
bool handshakeStarted = false;
uint8_t targetBSSID[6];
bool targetSet = false;
uint8_t targetChannel = 1;

bool isEAPOL(uint8_t* payload, uint16_t len) {
    if (len < 24) return false;
    if (payload[0] != 0x88) return false;
    if (payload[1] != 0x01) return false;
    return true;
}

uint8_t getHandshakeMsgNum(uint8_t* payload) {
    if (!isEAPOL(payload, 0)) return 0;
    uint16_t keyInfo = (payload[25] << 8) | payload[24];
    if (keyInfo & 0x0001) return 1;
    if (keyInfo & 0x0002) return 2;
    if (keyInfo & 0x0004) return 3;
    if (keyInfo & 0x0008) return 4;
    return 0;
}

void captureHandshake(uint8_t* payload, uint16_t len, uint8_t msgNum) {
    char pcapName[32];
    sprintf(pcapName, "/handshake_%02X%02X%02X%02X%02X%02X.pcap", 
            targetBSSID[0], targetBSSID[1], targetBSSID[2], 
            targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    
    handshakeFile = SD_MMC.open(pcapName, FILE_APPEND);
    if (!handshakeFile) return;

    uint32_t ts_sec = micros() / 1000000;
    uint32_t ts_usec = micros() % 1000000;
    uint32_t incl_len = len;
    uint32_t orig_len = len;

    handshakeFile.write((uint8_t*)&ts_sec, 4);
    handshakeFile.write((uint8_t*)&ts_usec, 4);
    handshakeFile.write((uint8_t*)&incl_len, 4);
    handshakeFile.write((uint8_t*)&orig_len, 4);
    handshakeFile.write(payload, len);
    handshakeFile.close();

    Serial.printf("[HANDSHAKE] Msg%d captured
", msgNum);
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (type == WIFI_PKT_MGMT) {
        if (payload[0] == 0x80) {
            uint8_t* bssid = &payload[10];
            uint8_t ch = payload[10 + 6];
            
            if (!targetSet) {
                memcpy(targetBSSID, bssid, 6);
                targetChannel = ch;
                targetSet = true;
                handshakeStarted = true;
                
                char macStr[18];
                sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                int ssid_len = payload[37];
                char ssid[33] = {0};
                if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid, &payload[38], ssid_len);
                Serial.printf("[TARGET] %s | %s | CH: %d
", ssid, macStr, ch);
                
                char pcapName[32];
                sprintf(pcapName, "/handshake_%02X%02X%02X%02X%02X%02X.pcap", 
                        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                handshakeFile = SD_MMC.open(pcapName, FILE_WRITE);
                if (handshakeFile) {
                    uint32_t magic = 0xa1b2c3d4;
                    uint16_t version_major = 2;
                    uint16_t version_minor = 4;
                    int32_t thiszone = 0;
                    uint32_t sigfigs = 0;
                    uint32_t snaplen = 65535;
                    uint32_t network = 105;
                    handshakeFile.write((uint8_t*)&magic, 4);
                    handshakeFile.write((uint8_t*)&version_major, 2);
                    handshakeFile.write((uint8_t*)&version_minor, 2);
                    handshakeFile.write((uint8_t*)&thiszone, 4);
                    handshakeFile.write((uint8_t*)&sigfigs, 4);
                    handshakeFile.write((uint8_t*)&snaplen, 4);
                    handshakeFile.write((uint8_t*)&network, 4);
                    handshakeFile.close();
                }
            }
            
            if (memcmp(bssid, targetBSSID, 6) == 0 && ch != targetChannel) {
                targetChannel = ch;
            }
        }
        
        if (handshakeStarted && isEAPOL(payload, len)) {
            uint8_t msgNum = getHandshakeMsgNum(payload);
            if (msgNum > 0) {
                char key[18];
                sprintf(key, "%02X%02X%02X%02X%02X%02X-Msg%d", 
                        targetBSSID[0], targetBSSID[1], targetBSSID[2], 
                        targetBSSID[3], targetBSSID[4], targetBSSID[5], msgNum);
                
                if (seenHandshakes.find(String(key)) == seenHandshakes.end()) {
                    seenHandshakes.insert(String(key));
                    digitalWrite(LED_PIN, LOW);
                    captureHandshake(payload, len, msgNum);
                    digitalWrite(LED_PIN, HIGH);
                    
                    if (seenHandshakes.size() >= 4) {
                        Serial.println("[!] COMPLETE HANDSHAKE CAPTURED");
                    }
                }
            }
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
    Serial.println("HANDSHAKE SNIFFER RUNNING");
    Serial.println("Waiting for target network...");
}

void loop() {
    if (targetSet) {
        esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    } else {
        static uint8_t ch = 1;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        ch = (ch % 13) + 1;
    }
    delay(100); 
}
