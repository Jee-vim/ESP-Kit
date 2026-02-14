#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>

#define AP_SSID "ESP32-AUDITOR"
#define AP_PASSWORD "12345678"

AsyncWebServer server(80);

extern uint32_t packetCount;
extern uint8_t currentChannel;

const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESP32 WiFi Auditor</title>
  <style>
    body { font-family: monospace; background: #1a1a1a; color: #eee; padding: 20px; }
    h1 { color: #00ff88; }
    .status { background: #2a2a2a; padding: 15px; margin: 20px 0; }
    .files { background: #2a2a2a; padding: 15px; }
    .file { padding: 10px; border-bottom: 1px solid #444; }
    a { color: #00aaff; }
  </style>
</head>
<body>
  <h1>ESP32 WiFi Auditor</h1>
  <div class="status">
    Channel: <span id="channel">1</span> | Packets: <span id="packets">0</span>
  </div>
  <div class="files">
    <h3>Files</h3>
    <div id="fileList"></div>
  </div>
  <script>
    function refreshFiles() {
      fetch("/api/files").then(r => r.text()).then(text => {
        document.getElementById("fileList").innerHTML = text;
      });
    }
    setInterval(() => {
      fetch("/api/status").then(r => r.json()).then(d => {
        document.getElementById("channel").innerText = d.channel;
        document.getElementById("packets").innerText = d.packets;
      });
    }, 1000);
    refreshFiles();
  </script>
</body>
</html>
)rawliteral";

void handleRoot(AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", INDEX_HTML);
}

void handleFileList(AsyncWebServerRequest *request) {
    String html = "";
    File root = SD_MMC.open("/");
    if (root) {
        File file = root.openNextFile();
        while (file) {
            String name = String(file.name());
            if (name.startsWith("/")) name = name.substring(1);
            if (name.length() > 0 && !name.startsWith(".")) {
                html += "<div class=\"file\"><span>" + name + "</span>";
                html += " <a href=\"/api/files/" + name + "\">Download</a></div>";
            }
            file = root.openNextFile();
        }
    }
    if (html == "") html = "<div class=\"file\">No files</div>";
    request->send(200, "text/html", html);
}

void handleStatus(AsyncWebServerRequest *request) {
    String json = "{\"channel\":" + String(currentChannel) + ",\"packets\":" + String(packetCount) + "}";
    request->send(200, "application/json", json);
}

void webui_init() {
    Serial.println("Starting AP...");
    boolean result = WiFi.softAP(AP_SSID, AP_PASSWORD);
    if (result) {
        Serial.print("AP IP: ");
        Serial.println(WiFi.softAPIP());
    } else {
        Serial.println("AP Failed!");
    }
    
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/files", HTTP_GET, handleFileList);
    server.on("/api/status", HTTP_GET, handleStatus);
    
    server.begin();
    Serial.println("Web server started");
}
