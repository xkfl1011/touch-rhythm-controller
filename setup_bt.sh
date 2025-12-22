#!/bin/bash

echo "=== Raspberry Pi 5 Bluetooth HID Setup Script ==="

# 1. Install required packages
echo "[1/5] Installing required tools..."
sudo apt-get update
sudo apt-get install -y bluez bluez-tools bluez-firmware

# 2. Modify Bluetooth service settings (--noplugin=input and -C compatibility mode)
echo "[2/5] Modifying Bluetooth service settings..."
SERVICE_FILE="/lib/systemd/system/bluetooth.service"

# Check if already configured to avoid duplicate entries
if grep -q "noplugin=input" "$SERVICE_FILE"; then
    echo "  - Already configured."
else
    # Find ExecStart line and append options
    sudo sed -i 's|ExecStart=/usr/lib/bluetooth/bluetoothd|ExecStart=/usr/lib/bluetooth/bluetoothd -C --noplugin=input|g' "$SERVICE_FILE"
    echo "  - Configuration updated."
fi

# 3. Restart Service
echo "[3/5] Restarting Bluetooth daemon..."
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
sleep 2

# 4. Set Python Permissions (to open sockets without sudo)
echo "[4/5] Setting Python permissions..."
PYTHON_PATH=$(readlink -f $(which python3))
# Apply capabilities to the python binary
sudo setcap 'cap_net_raw,cap_net_admin+eip' "$PYTHON_PATH"

# 5. Force Bluetooth Device Class (Peripheral/Keyboard/Mouse)
echo "[5/5] Setting Device Class (CoD)..."
# Ensure interface is up
sudo hciconfig hci0 up
# Class 0x0025C0: Peripheral (Major) + Keyboard/Pointing (Minor)
sudo hciconfig hci0 class 0x0025C0
# Enable Secure Simple Pairing
sudo hciconfig hci0 sspmode 1
# Enable Page and Inquiry Scan (Discoverable)
sudo hciconfig hci0 piscan

echo "=== Setup Complete! You can now run the Python script. ==="