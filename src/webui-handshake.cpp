#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include "FS.h"
#include "SD_MMC.h"
#include "soc/rtc_cntl_reg.h"
#include "soc/soc.h"
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <set>

#define AP_SSID "ESP32-AUDITOR"
#define AP_PASSWORD "12345678"

AsyncWebServer server(80);

extern uint32_t packetCount;
extern uint8_t currentChannel;
extern bool targetSet;
extern bool handshakeComplete;
extern uint8_t targetChannel;

const char INDEX_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESP32 Handshake Capture</title>
  <style>
    body { font-family: monospace; background: #1a1a1a; color: #eee; padding: 20px; }
    h1 { color: #00ff88; }
    .status { background: #2a2a2a; padding: 15px; margin: 20px 0; }
    .files { background: #2a2a2a; padding: 15px; margin: 20px 0; }
    .file { padding: 10px; border-bottom: 1px solid #444; }
    a { color: #00aaff; }
    .btn { background: #00aaff; color: #fff; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }
    .btn-stop { background: #ff4444; }
    .complete { color: #00ff88; font-weight: bold; }
  </style>
</head>
<body>
  <h1>ESP32 Handshake Capture</h1>
  <div class="status">
    Status: <span id="status">Waiting...</span><br>
    Target: <span id="target">None</span><br>
    Channel: <span id="channel">-</span><br>
    Handshakes: <span id="hs">0</span>
  </div>
  <div class="files">
    <h3>Captured Files</h3>
    <div id="fileList"></div>
  </div>
  <script>
    let hsCount = 0;
    function refreshFiles() {
      fetch("/api/files").then(r => r.text()).then(text => {
        document.getElementById("fileList").innerHTML = text;
      });
    }
    setInterval(() => {
      fetch("/api/status").then(r => r.json()).then(d => {
        document.getElementById("channel").innerText = d.channel;
        if (d.targetSet) {
          document.getElementById("target").innerText = d.targetMAC;
          document.getElementById("status").innerText = d.complete ? "COMPLETE" : "Capturing...";
          document.getElementById("hs").innerText = d.hsCount;
        } else {
          document.getElementById("status").innerText = "Scanning...";
        }
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
            if (name.length() > 0 && !name.startsWith(".") && (name.startsWith("handshake") || name.startsWith("capture"))) {
                html += "<div class=\"file\"><span>" + name + "</span>";
                html += " <a href=\"/api/files/" + name + "\">Download</a></div>";
            }
            file = root.openNextFile();
        }
    }
    if (html == "") html = "<div class=\"file\">No captures yet</div>";
    request->send(200, "text/html", html);
}

void handleStatus(AsyncWebServerRequest *request) {
    extern uint8_t targetBSSID[6];
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
            targetBSSID[0], targetBSSID[1], targetBSSID[2], 
            targetBSSID[3], targetBSSID[4], targetBSSID[5]);
    
    extern std::set<String> seenHandshakes;
    String json = "{\"channel\":" + String(targetChannel) + ",\"targetSet\":" + String(targetSet ? "true" : "false") + ",\"targetMAC\":\"" + String(macStr) + "\",\"complete\":" + String(handshakeComplete ? "true" : "false") + ",\"hsCount\":" + String(seenHandshakes.size()) + "}";
    request->send(200, "application/json", json);
}

void webui_init() {
    Serial.println("Starting AP...");
    boolean result = WiFi.softAP(AP_SSID, AP_PASSWORD);
    if (result) {
        Serial.print("Web: http://");
        Serial.println(WiFi.softAPIP());
    }
    
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/files", HTTP_GET, handleFileList);
    server.on("/api/status", HTTP_GET, handleStatus);
    
    server.begin();
}
