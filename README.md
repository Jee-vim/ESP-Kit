# ESP-Kit

> Requires ESP32-CAM

Multi-tool ESP32 security platform.

## File Structure

| Module | Description | Tested  |
| --- | --- | --- |
| `sniffer.cpp` | Captures WiFi packets to SD card | Yes |
| `deauth.cpp` | Auto-deauths WiFi networks | No |
| `deauth-handshake.cpp` | Deauth clients + capture handshake | No |
| `deauth-ap-handshake.cpp` | Fake AP + deauth + capture handshake | No |
| `pmkid.cpp` | Captures PMKID from association requests | No |
| `motion.cpp` | Motion-triggered photo capture | Yes |
| `stream.cpp` | Continuous camera streaming via web | Yes |


## How It Works

Each .cpp file is a standalone firmware. Only one runs at a time.

### sniffer.cpp
- Enables WiFi promiscuous mode
- Hops channels 1-13 every second
- Detects beacon frames (WiFi networks)
- Saves to SD:
  - /capture.pcap - Raw packets (Wireshark)
- LED on GPIO 33 flashes during writes

### deauth.cpp
- Enables WiFi promiscuous mode
- Hops channels 1-13 every second
- Detects beacon frames
- Sends deauth frames to:
  - ALL networks (default)
  - Specific target (set TARGET_MAC)
- LED on GPIO 33 flashes during deauth


### deauth-handshake.cpp
- Deauths clients from target network
- Captures handshake when devices reconnect to real AP
- Stops when full handshake (4 messages) captured
- Saves to /handshake/XXXXXXXXXXXX.pcap on SD
- LED on GPIO 33 flashes during capture

### deauth-ap-handshake.cpp
- Deauths clients from target network
- Creates fake AP with target SSID
- Captures WPA handshake when clients reconnect
- Saves to /handshake/XXXXXXXXXXXX.pcap on SD
- LED on GPIO 33 flashes on capture

### pmkid.cpp
- Sniffs association/reassociation requests for RSN IE
- Extracts PMKID if present
- Saves to /pmkid.txt in hashcat format
- Format: PMKID*BSSID*CLIENT_MAC*SSID
- Stops after first capture

### motion.cpp
- Captures photo when motion detected
- Compares pixel differences between frames
- Saves to /motion/<timestamp>.jpg on SD
- Configurable threshold (20) and cooldown (5s)
- LED on GPIO 33 flashes on capture

### stream.cpp
- Continuous camera streaming via web browser
- Creates WiFi AP (SSID: ESP-Kit, Pass: 12345678)
- Access at http://192.168.4.1
- MJPEG streaming at /stream endpoint

## Flash Mode

1. Hold reset button
2. Connect GPIO 0 to GND
3. Release reset when see "Connecting..."
4. Done

## Commands

# Erase flash (first time)
```bash
pio run --target erase
```

# Build & Upload specific script
```bash 
pio run -e sniffer --target upload
pio run -e deauth --target upload
pio run -e deauth-handshake --target upload
pio run -e deauth-ap-handshake --target upload
pio run -e pmkid --target upload
pio run -e motion --target upload
pio run -e stream --target upload
```

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

## Access SD Card

```bash
# Mount (adjust /dev/sdb as needed)
sudo mkdir -p /mnt/sdcard
sudo mount -o ro /dev/sdb /mnt/sdcard
cd /mnt/sdcard

# Unmount before removing
sudo umount /mnt/sdcard
```

## TODO
- Smart Device Takeover
