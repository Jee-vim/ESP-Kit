{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    platformio
    esptool
    python3Packages.pyserial
  ];

  shellHook = ''
    echo "ESP32-CAM Flashing Environment"
    echo "Ready to use esptool."
  '';
}
