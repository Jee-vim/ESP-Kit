#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include <time.h>
#include <set>

#define PCAP_BUFFER_SIZE 1024  // Buffer size in bytes
#define PCAP_MAX_PACKETS 10    // Max packets per buffer

#define LED_PIN 33

std::set<String> seenMACs;
File pcapFile;
String pcapFilename;
bool pcapInitialized = false;
uint32_t packetCount = 0;
uint8_t currentChannel = 1;

// SD card buffering
uint8_t pcapBuffer[PCAP_BUFFER_SIZE];
uint16_t bufferPos = 0;  // Current position in buffer

#ifdef WEBUI
extern void webui_init();
#endif

// SD card error recovery retry count
#define SD_RETRIES 3

void initPcapHeader() {
    for (int retry = 0; retry < SD_RETRIES; retry++) {
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
        break;  // Success, exit retry loop
    } else {
        Serial.println("[SD] Retry " + String(retry + 1) + " failed");
        delay(100);
    }
}
if (!pcapInitialized) {
    Serial.println("[SD] Init FAILED after " + String(SD_RETRIES) + " retries");
}

void writePcapPacket(const uint8_t* payload, uint16_t len) {
    // Skip packet if buffer full or file not ready
    if (!pcapInitialized || len > 2560) return;
    
    // Ensure we have enough space for packet + header
    if (bufferPos + len + 16 >= PCAP_BUFFER_SIZE) {
        flushPcapBuffer();
    }
    
    // Add timestamp header
    uint32_t ts_sec = micros() / 1000000;
    uint32_t ts_usec = micros() % 1000000;
    uint32_t incl_len = len;
    uint32_t orig_len = len;
    
    memcpy(pcapBuffer + bufferPos, &ts_sec, 4);
    bufferPos += 4;
    memcpy(pcapBuffer + bufferPos, &ts_usec, 4);
    bufferPos += 4;
    memcpy(pcapBuffer + bufferPos, &incl_len, 4);
    bufferPos += 4;
    memcpy(pcapBuffer + bufferPos, &orig_len, 4);
    bufferPos += 4;
    
    // Copy packet data
    memcpy(pcapBuffer + bufferPos, payload, len);
    bufferPos += len;
    
    // Flush buffer if it's getting full (90% full)
    if (bufferPos > PCAP_BUFFER_SIZE * 9 / 10) {
        flushPcapBuffer();
    }
}

void flushPcapBuffer() {
    if (bufferPos == 0) return;
    
    if (!pcapFile) {
        // Retry opening file
        for (int retry = 0; retry < SD_RETRIES; retry++) {
            pcapFile = SD_MMC.open(pcapFilename.c_str(), FILE_APPEND);
            if (pcapFile) {
                break;
            }
            Serial.println("[SD] File re-open retry " + String(retry + 1));
            delay(50);
        }
        if (!pcapFile) {
            bufferPos = 0;
            Serial.println("[SD] Failed to reopen file");
            return;
        }
    }
    
    // Write with error checking
    size_t written = pcapFile.write(pcapBuffer, bufferPos);
    if (written != bufferPos) {
        Serial.printf("[SD] Write incomplete: %u of %u bytes
", written, bufferPos);
    }
    pcapFile.flush();
    bufferPos = 0;
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    packetCount++;

    if (type == WIFI_PKT_MGMT && payload[0] == 0x80) {
        uint8_t* bssid = &payload[10];
        char macStr[18];
        sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

        if (seenMACs.find(String(macStr)) == seenMACs.end()) {
            seenMACs.insert(String(macStr));
            int ssid_len = payload[37];
            char ssid[33] = {0};
            if (ssid_len > 0 && ssid_len <= 32) memcpy(ssid, &payload[38], ssid_len);

            uint8_t ch = currentChannel;  // Use tracked channel instead of WiFi.channel() for promiscuous mode

            Serial.printf("\n[NEW] %s | %s | CH: %d\n> ", ssid, macStr, ch);
        }
    }

    if (pcapInitialized && len > 0 && len < 2560) {
        digitalWrite(LED_PIN, LOW);
        writePcapPacket(payload, len);
        digitalWrite(LED_PIN, HIGH);
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    Serial.begin(115200);

    time_t now = time(nullptr);
    struct tm* ti = localtime(&now);
    char fname[64];
    snprintf(fname, sizeof(fname), "/sniffer/%04d%02d%02d-%02d%02d%02d.pcap",
             ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
             ti->tm_hour, ti->tm_min, ti->tm_sec);
    pcapFilename = String(fname);

    if (SD_MMC.begin("/sdcard", true)) {
        Serial.println("SD: OK");
        SD_MMC.mkdir("/sniffer");
        initPcapHeader();
        Serial.printf("Saving to: %s\n", fname);
    } else {
        Serial.println("SD: FAILED");
    }

#ifdef WEBUI
    webui_init();
#endif

    WiFi.mode(WIFI_AP_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("SNIFFER RUNNING");
}

void loop() {
    static uint8_t ch = 1;
    currentChannel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    ch = (ch % 13) + 1;
    delay(1000);
}
