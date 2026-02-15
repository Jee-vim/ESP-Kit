# ESP32-WiFi-Tool

WiFi auditing tools for ESP32-CAM.

## File Structure

```
src/
├── sniffer.cpp         # Captures WiFi packets to SD card
├── deauth.cpp          # Auto-deauths WiFi networks
├── handshake.cpp       # Captures WPA handshakes (passive)
├── handshake-auto.cpp  # Auto-deauths clients + captures handshake
├── pmkid.cpp           # Captures PMKID from association requests
├── webui.cpp          # Web UI for sniffer (combines with sniffer)
└── webui-handshake.cpp # Web UI for handshake-auto
```

## How It Works

Each .cpp file is a standalone firmware. Only one runs at a time.

### sniffer.cpp
- Enables WiFi promiscuous mode
- Hops channels 1-13 every second
- Detects beacon frames (WiFi networks)
- Saves to SD:
  - /capture.pcap - Raw packets (Wireshark)
  - /networks.txt - Parsed: SSID|MAC|CH
- LED on GPIO 33 flashes during writes

### deauth.cpp
- Enables WiFi promiscuous mode
- Hops channels 1-13 every second
- Detects beacon frames
- Sends deauth frames to:
  - ALL networks (default)
  - Specific target (set TARGET_MAC)
- LED on GPIO 33 flashes during deauth

### handshake.cpp (Passive)
- Sniffs for WPA handshakes
- First detected network becomes target
- Stays on target channel
- Captures EAPOL packets when clients connect naturally
- Saves to: /handshake_XXXXXXXXXXXX.pcap

### handshake-auto.cpp (Auto)
- First network detected = target
- Auto-sends deauth every 5 seconds (broadcast to all clients)
- Captures handshake when devices reconnect
- Stops when full handshake (4 messages) captured
- Also saves to /capture.pcap
- LED on GPIO 33 flashes during capture

### pmkid.cpp (NEW)
- Sniffs association/reassociation requests for RSN IE
- Extracts PMKID if present
- Saves to /pmkid.txt in hashcat format
- Format: PMKID*BSSID*CLIENT_MAC*SSID
- Stops after first capture

### sniffer-web (NEW)
- Combines sniffer.cpp + webui.cpp
- Runs WiFi AP (SSID: ESP32-AUDITOR, password: 12345678)
- Serves captured files via web browser
- Access at http://192.168.4.1

### handshake-web (NEW)
- Combines handshake-auto.cpp + webui-handshake.cpp
- Shows target status, handshake capture progress
- Download captured handshakes from browser
- Access at http://192.168.4.1

## Flash Mode

1. Hold reset button
2. Connect GPIO 0 to GND
3. Release reset when see "Connecting..."
4. Done

## Commands

# Erase flash (first time)
pio run --target erase

# Build & Upload specific script
pio run -e sniffer --target upload
pio run -e deauth --target upload
pio run -e handshake --target upload
pio run -e handshake-auto --target upload
pio run -e pmkid --target upload
pio run -e sniffer-web --target upload
pio run -e handshake-web --target upload

# Monitor serial output
pio device monitor

## Default Target

Edit platformio.ini:

[platformio]
default_envs = sniffer

## deauth.cpp Configuration

// Deauth ALL networks
#define TARGET_MAC ""

// Specific target
#define TARGET_MAC "AA:BB:CC:DD:EE:FF"

## Cracking

### Handshake
After capturing handshake:

# Convert to hashcat format
hcxpcapngtool -o hash.hccapx handshake_*.pcap

# Crack with hashcat
hashcat -m 22000 hash.hccapx wordlist.txt

### PMKID
After capturing PMKID (in pmkid.txt):

# Crack with hashcat (mode 22000)
hashcat -m 22000 pmkid.txt wordlist.txt
