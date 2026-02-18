#include <time.h>
#include <Arduino.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"

#if CONFIG_ESP32_CAMERA_ENABLED
#include "esp_camera.h"
#endif

#define LED_PIN 33
String photoPrefix;
#define MOTION_THRESHOLD 20
#define MOTION_COOLDOWN 5000

#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

uint32_t lastCaptureTime = 0;
uint8_t* baselineFrame = nullptr;
bool baselineSet = false;
camera_fb_t* fb = nullptr;

void initCamera() {
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer = LEDC_TIMER_0;
    config.pin_d0 = Y2_GPIO_NUM;
    config.pin_d1 = Y3_GPIO_NUM;
    config.pin_d2 = Y4_GPIO_NUM;
    config.pin_d3 = Y5_GPIO_NUM;
    config.pin_d4 = Y6_GPIO_NUM;
    config.pin_d5 = Y7_GPIO_NUM;
    config.pin_d6 = Y8_GPIO_NUM;
    config.pin_d7 = Y9_GPIO_NUM;
    config.pin_xclk = XCLK_GPIO_NUM;
    config.pin_pclk = PCLK_GPIO_NUM;
    config.pin_vsync = VSYNC_GPIO_NUM;
    config.pin_href = HREF_GPIO_NUM;
    config.pin_sccb_sda = SIOD_GPIO_NUM;
    config.pin_sccb_scl = SIOC_GPIO_NUM;
    config.pin_pwdn = PWDN_GPIO_NUM;
    config.pin_reset = RESET_GPIO_NUM;
    config.xclk_freq_hz = 20000000;
    config.frame_size = FRAMESIZE_SVGA;
    config.pixel_format = PIXFORMAT_JPEG;
    config.grab_mode = CAMERA_GRAB_WHEN_EMPTY;
    config.fb_location = CAMERA_FB_IN_PSRAM;
    config.jpeg_quality = 12;
    config.fb_count = 2;

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("[CAMERA] Init failed: %s\n", esp_err_to_name(err));
        return;
    }
    Serial.println("[CAMERA] Init OK");
}

bool detectMotion(uint8_t* current, size_t len) {
    if (!baselineSet || !baselineFrame || len < 1000) return false;

    size_t skip = 200;
    size_t cmpLen = len > skip ? min((size_t)10000, len - skip) : 0;
    if (cmpLen < 100) return false;

    uint32_t diff = 0;
    for (size_t i = 0; i < cmpLen; i++) {
        int d = baselineFrame[skip + i] - current[skip + i];
        if (d < 0) d = -d;
        diff += d;
    }

    uint32_t avgDiff = diff / cmpLen;
    Serial.printf("[MOTION] Avg diff: %d\n", avgDiff);

    return avgDiff > MOTION_THRESHOLD;
}

void savePhoto(camera_fb_t* fb) {
    char filename[64];
    uint32_t ts = millis();
    snprintf(filename, sizeof(filename), "%s-%lu.jpg", photoPrefix.c_str(), ts);

    File file = SD_MMC.open(filename, FILE_WRITE);
    if (!file) {
        Serial.println("[SD] Failed to open file");
        return;
    }

    file.write(fb->buf, fb->len);
    file.close();

    Serial.printf("[CAPTURE] Saved %s (%d bytes)\n", filename, fb->len);
    digitalWrite(LED_PIN, LOW);
    delay(100);
    digitalWrite(LED_PIN, HIGH);
}

void cleanupBaseline() {
    if (baselineFrame) {
        free(baselineFrame);
        baselineFrame = nullptr;
        baselineSet = false;
        Serial.println("[BASELINE] Cleaned up");
    }
}

void setBaseline(camera_fb_t* fb) {
    cleanupBaseline();  // Clean up old baseline first
    baselineFrame = (uint8_t*)malloc(fb->len);
    if (baselineFrame) {
        memcpy(baselineFrame, fb->buf, fb->len);
        baselineSet = true;
        Serial.println("[BASELINE] Set");
    } else {
        Serial.println("[BASELINE] Memory allocation failed");
    }
}

void setup() {
    WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);

    Serial.begin(115200);
    delay(1000);
    Serial.println("\n[MOTION] Starting...");
    Serial.flush();

    if (!SD_MMC.begin("/sdcard", true)) {
        Serial.println("[SD] Init FAILED");
    } else {
        Serial.println("[SD] Init OK");
        time_t now = time(nullptr);
        struct tm* ti = localtime(&now);
        char prefix[64];
        snprintf(prefix, sizeof(prefix), "/motion/%04d%02d%02d-%02d%02d%02d",
                 ti->tm_year + 1900, ti->tm_mon + 1, ti->tm_mday,
                 ti->tm_hour, ti->tm_min, ti->tm_sec);
        photoPrefix = String(prefix);
        SD_MMC.mkdir("/motion");
    }

    initCamera();

    delay(3000);
    fb = esp_camera_fb_get();
    if (fb) {
        setBaseline(fb);
        esp_camera_fb_return(fb);
    }

    Serial.println("[MOTION] Running - waiting for motion...");
    
    // Clear baseline at end of setup to free memory from initial frame
    cleanupBaseline();
}

void loop() {
    uint32_t now = millis();

    fb = esp_camera_fb_get();
    if (!fb) {
        Serial.println("[CAMERA] Frame failed");
        delay(1000);
        return;
    }

    if (now > 5000 && detectMotion(fb->buf, fb->len)) {
        if (now - lastCaptureTime > MOTION_COOLDOWN) {
            Serial.println("[MOTION] DETECTED!");
            savePhoto(fb);
            lastCaptureTime = now;
            setBaseline(fb);
        }
    }

    esp_camera_fb_return(fb);
    delay(500);
}
