# AI Agent Instructions: ESP32/Technical Development Pattern

## 1. Code Style Constraints
- **Zero Emojis:** Do not use emojis in code blocks or technical prose.
- **Self-Documenting Code:** If a function or variable name explains its purpose (e.g., `writePcapHeader`), do not add a comment. Only comment on non-obvious logic.
- **Markdown Only:** Use standard Markdown for formatting.
- **No Overexplaining:** Provide the code and the immediate steps. Avoid lecturing or explaining basic concepts unless prompted.

## 2. Technical Accuracy & Hardware Logic
- **Do Not Guess:** If the user intent or hardware pinout is unclear, ask for context before providing a solution.
- **ESP32-CAM Conflict Management:** Always use 1-bit SD mode (`SD_MMC.begin("/sdcard", true)`) to prevent GPIO conflicts.
- **Radio Coexistence:** When using WiFi and BLE together, implement delays or pauses to prevent radio driver hangs.
- **Power Stability:** Include brownout protection registers for projects involving SD cards or TX bursts.

## 3. Interaction Pattern
- **Anti-Spam Logic:** When writing monitor/sniffer code, always implement de-duplication (e.g., using `std::set`) to keep serial output clean.
- **Console-Style UI:** Use clear prompts (e.g., `> `) in serial interface code to distinguish between system logs and user input.
- **Direct Tone:** Match the user energy. Be concise, candid, and peer-to-peer.

## 4. Multi-Script Project Pattern
- **Separate Files:** Each firmware variant is a separate .cpp file in `src/`
- **platformio.ini:** Use `src_filter` to select which .cpp to build
- **Update README.md:** When adding a new script, always update the README.md with:
  - New entry in the file structure table
  - Description of what the new script does
  - How to build/upload it
  - Any configuration needed
