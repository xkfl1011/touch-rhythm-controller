import sys
import os
import socket
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import threading
import time

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QGridLayout, QStackedLayout)
from PyQt6.QtCore import Qt, QEvent, QPointF, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPalette, QTouchEvent

# ==========================================
# 1. Bluetooth HID Constants & Descriptors
# ==========================================

# SDP Record for HID (Keyboard + Mouse Combo)
sdp_record_xml = """
<?xml version="1.0" encoding="UTF-8" ?>
<record>
  <attribute id="0x0001">
    <sequence>
      <uuid value="0x1124" />
    </sequence>
  </attribute>
  <attribute id="0x0004">
    <sequence>
      <sequence>
        <uuid value="0x0100" />
      </sequence>
      <sequence>
        <uuid value="0x0011" />
      </sequence>
      <sequence>
        <uuid value="0x0013" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0005">
    <sequence>
      <uuid value="0x1002" />
    </sequence>
  </attribute>
  <attribute id="0x0006">
    <sequence>
      <uint16 value="0x656e" />
      <uint16 value="0x006a" />
      <uint16 value="0x0100" />
    </sequence>
  </attribute>
  <attribute id="0x0009">
    <sequence>
      <sequence>
        <uuid value="0x1124" />
        <uint16 value="0x0101" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x000d">
    <sequence>
      <sequence>
        <sequence>
          <uuid value="0x0100" />
          <uint16 value="0x0011" />
        </sequence>
        <sequence>
          <uuid value="0x0011" />
        </sequence>
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0100">
    <text value="RPi Touch HID" />
  </attribute>
  <attribute id="0x0101">
    <text value="Raspberry Pi 5" />
  </attribute>
  <attribute id="0x0200">
    <uint16 value="0x0101" />
  </attribute>
  <attribute id="0x0201">
    <uint16 value="0x0101" />
  </attribute>
  <attribute id="0x0202">
    <uint8 value="0x80" />
  </attribute>
  <attribute id="0x0203">
    <uint8 value="0x33" />
  </attribute>
  <attribute id="0x0204">
    <boolean value="true" />
  </attribute>
  <attribute id="0x0205">
    <boolean value="true" />
  </attribute>
  <attribute id="0x0206">
    <sequence>
      <sequence>
        <uint8 value="0x22" />
        <text value="Report" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x0207">
    <sequence>
      <sequence>
        <uint8 value="0x22" />
        <text value="Report" />
      </sequence>
    </sequence>
  </attribute>
  <attribute id="0x020b">
    <uint16 value="0x0100" />
  </attribute>
  <attribute id="0x020c">
    <uint16 value="0x0c80" />
  </attribute>
  <attribute id="0x020d">
    <boolean value="false" />
  </attribute>
</record>
"""

# BlueZ DBus Paths
BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
BLUEZ_PROFILE_MGR_IFACE = "org.bluez.ProfileManager1"
BLUEZ_PROFILE_IFACE = "org.bluez.Profile1"

# HID Report Codes
KEY_MOD_LCTRL = 0x01
KEY_MOD_LSHIFT = 0x02
KEY_MOD_LALT = 0x04
KEY_MOD_LMETA = 0x08

# Simple Key Map (Char -> HID Code)
HID_MAP = {
    'a': 0x04, 'b': 0x05, 'c': 0x06, 'd': 0x07, 'e': 0x08, 'f': 0x09, 'g': 0x0a, 'h': 0x0b,
    'i': 0x0c, 'j': 0x0d, 'k': 0x0e, 'l': 0x0f, 'm': 0x10, 'n': 0x11, 'o': 0x12, 'p': 0x13,
    'q': 0x14, 'r': 0x15, 's': 0x16, 't': 0x17, 'u': 0x18, 'v': 0x19, 'w': 0x1a, 'x': 0x1b,
    'y': 0x1c, 'z': 0x1d, '1': 0x1e, '2': 0x1f, '3': 0x20, '4': 0x21, '5': 0x22, '6': 0x23,
    '7': 0x24, '8': 0x25, '9': 0x26, '0': 0x27, 'ENTER': 0x28, 'ESC': 0x29, 'BACK': 0x2a,
    'TAB': 0x2b, 'SPACE': 0x2c, '-': 0x2d, '=': 0x2e, '[': 0x2f, ']': 0x30, '\\': 0x31,
    ';': 0x33, '\'': 0x34, '`': 0x35, ',': 0x36, '.': 0x37, '/': 0x38,
    'F1': 0x3a, 'F2': 0x3b, 'UP': 0x52, 'DOWN': 0x51, 'LEFT': 0x50, 'RIGHT': 0x4f
}

# ==========================================
# 2. Bluetooth Service Class (Backend)
# ==========================================

class BTProfile(dbus.service.Object):
    def __init__(self, bus, path, fd):
        dbus.service.Object.__init__(self, bus, path)
        self.fd = fd

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="", out_signature="")
    def Release(self):
        print("Release")

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="", out_signature="")
    def Cancel(self):
        print("Cancel")

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="oha{sv}", out_signature="")
    def NewConnection(self, path, fd, properties):
        self.fd = fd.take()
        print(f"NewConnection: {path}")

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="o", out_signature="")
    def RequestDisconnection(self, path):
        print(f"RequestDisconnection: {path}")
        if self.fd > 0:
            os.close(self.fd)
            self.fd = -1

class BluetoothHIDService(threading.Thread):
    def __init__(self):
        super().__init__()
        self.c_socket = None # Control socket
        self.i_socket = None # Interrupt socket
        self.running = True
        self.connected = False

    def run(self):
        # Setting up DBus loop in a separate thread
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()
        self.adapter_path = "/org/bluez/hci0" # Default adapter
        
        # Configure Adapter (Simplistic)
        adapter = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, self.adapter_path), DBUS_PROP_IFACE)
        adapter.Set(BLUEZ_SERVICE_NAME + ".Adapter1", "Powered", dbus.Boolean(1))
        adapter.Set(BLUEZ_SERVICE_NAME + ".Adapter1", "Discoverable", dbus.Boolean(1))
        adapter.Set(BLUEZ_SERVICE_NAME + ".Adapter1", "Alias", "RPi5-Touch-HID")

        # Setup Profile
        profile_path = "/org/bluez/hci0/hid_profile"
        profile = BTProfile(self.bus, profile_path, -1)
        
        manager = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez"), BLUEZ_PROFILE_MGR_IFACE)
        
        opts = {
            "ServiceRecord": sdp_record_xml,
            "Role": "server",
            "RequireAuthentication": dbus.Boolean(True),
            "RequireAuthorization": dbus.Boolean(True)
        }
        
        manager.RegisterProfile(profile_path, "00001124-0000-1000-8000-00805f9b34fb", opts)
        
        print("Bluetooth Profile Registered. Waiting for connections...")
        self.listen_sockets()

    def listen_sockets(self):
        # Listen on L2CAP ports 17 (Control) and 19 (Interrupt)
        c_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
        i_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_L2CAP)
        
        c_sock.bind((socket.BDADDR_ANY, 17))
        i_sock.bind((socket.BDADDR_ANY, 19))
        
        c_sock.listen(1)
        i_sock.listen(1)
        
        while self.running:
            print("Waiting for Bluetooth connection...")
            try:
                self.c_socket, c_info = c_sock.accept()
                self.i_socket, i_info = i_sock.accept()
                print(f"Accepted connection from {c_info[0]}")
                self.connected = True
                
                # Keep alive check or wait until disconnect
                while self.connected:
                    time.sleep(1)
                    try:
                        # Simple check if socket is alive
                        self.c_socket.getpeername()
                    except:
                        print("Connection lost.")
                        self.connected = False
                        
                self.c_socket.close()
                self.i_socket.close()
            except Exception as e:
                print(f"Socket Error: {e}")
                time.sleep(1)

    def send_keyboard_report(self, modifier, keys):
        if not self.connected or not self.i_socket:
            return
        # Report ID 1 (Keyboard) + Modifier + Reserved + Key1..Key6
        report = bytes([0xA1, 0x01, modifier, 0x00] + keys + [0x00] * (6 - len(keys)))
        try:
            self.i_socket.send(report)
        except:
            self.connected = False

    def send_mouse_report(self, buttons, x, y, wheel=0):
        if not self.connected or not self.i_socket:
            return
        # Report ID 2 (Mouse) + Buttons + X + Y + Wheel
        # Clamp values to -127 to 127
        x = max(-127, min(127, x))
        y = max(-127, min(127, y))
        
        # Conversion to signed byte
        bx = x & 0xff
        by = y & 0xff
        bw = wheel & 0xff
        
        report = bytes([0xA1, 0x02, buttons, bx, by, bw])
        try:
            self.i_socket.send(report)
        except:
            self.connected = False

# ==========================================
# 3. UI Widgets (Frontend)
# ==========================================

class TouchPad(QWidget):
    def __init__(self, bt_service):
        super().__init__()
        self.bt = bt_service
        self.setStyleSheet("background-color: #333333; border-radius: 10px; border: 2px solid #555;")
        self.setAttribute(Qt.WidgetAttribute.WA_AcceptTouchEvents, True)
        
        self.touch_points = {} # ID -> start_pos
        self.last_pos = None
        self.scrolling = False
        
        # Labels
        self.label = QLabel("Touchpad Area\n1 Finger: Move/Tap-Click\n2 Fingers: Scroll\nLong Press 2 Fingers: Right Click", self)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("color: #888; border: none;")
        
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        self.setLayout(layout)

    def event(self, event):
        # Handle Touch Events for Gestures
        if event.type() in [QEvent.Type.TouchBegin, QEvent.Type.TouchUpdate, QEvent.Type.TouchEnd]:
            self.handle_touch(event)
            return True
        return super().event(event)

    def handle_touch(self, event):
        points = event.touchPoints()
        
        if event.type() == QEvent.Type.TouchBegin:
            self.last_pos = points[0].position()
            if len(points) == 2:
                self.scrolling = True
            else:
                self.scrolling = False
                
        elif event.type() == QEvent.Type.TouchUpdate:
            if len(points) == 1 and not self.scrolling:
                # Mouse Move
                curr = points[0].position()
                delta_x = int((curr.x() - self.last_pos.x()) * 1.5) # Sensitivity
                delta_y = int((curr.y() - self.last_pos.y()) * 1.5)
                
                if abs(delta_x) > 0 or abs(delta_y) > 0:
                    self.bt.send_mouse_report(0, delta_x, delta_y, 0)
                self.last_pos = curr
                
            elif len(points) == 2:
                # Scroll (Use Y delta of first finger)
                curr = points[0].position()
                delta_y = int((curr.y() - self.last_pos.y()) * 0.5)
                if abs(delta_y) > 0:
                     # Scroll usually inverted or handled as wheel
                    self.bt.send_mouse_report(0, 0, 0, delta_y)
                self.last_pos = curr

        elif event.type() == QEvent.Type.TouchEnd:
            # Simple Tap Detection (if barely moved)
            if len(points) == 1 and not self.scrolling:
                # Check logic for tap could be added here (e.g. time duration)
                pass 
            self.scrolling = False

    # Fallback to mouse events if touch not recognized properly or for single click
    def mousePressEvent(self, e):
        # Left click
        self.bt.send_mouse_report(1, 0, 0, 0) # Button 1 down

    def mouseReleaseEvent(self, e):
        self.bt.send_mouse_report(0, 0, 0, 0) # Buttons up

class VirtualKeyboard(QWidget):
    def __init__(self, bt_service):
        super().__init__()
        self.bt = bt_service
        self.layout = QGridLayout()
        self.setLayout(self.layout)
        
        # Define Keyboard Layout
        keys = [
            ['ESC', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'BACK'],
            ['TAB', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '\\'],
            ['A-LOCK', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', 'ENTER'],
            ['SHIFT', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'UP'],
            ['CTRL', 'WIN', 'ALT', 'SPACE', 'LEFT', 'DOWN', 'RIGHT']
        ]
        
        self.shift_pressed = False
        self.ctrl_pressed = False
        self.alt_pressed = False
        
        row = 0
        for key_row in keys:
            col = 0
            for key_char in key_row:
                btn = QPushButton(key_char)
                btn.setFixedSize(60, 50)
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #444; color: white; border-radius: 5px; font-size: 16px;
                    }
                    QPushButton:pressed {
                        background-color: #0078d7;
                    }
                """)
                # Handle special keys differently in layout if needed (like Space)
                if key_char == 'SPACE':
                    self.layout.addWidget(btn, row, col, 1, 4)
                    col += 4
                else:
                    self.layout.addWidget(btn, row, col)
                    col += 1
                
                # Connect click
                btn.pressed.connect(lambda k=key_char: self.on_key_press(k))
                btn.released.connect(lambda k=key_char: self.on_key_release(k))
            row += 1

    def on_key_press(self, key):
        mod = 0
        hid_code = 0
        
        # Toggle Modifiers logic
        if key == 'SHIFT': self.shift_pressed = True
        elif key == 'CTRL': self.ctrl_pressed = True
        elif key == 'ALT': self.alt_pressed = True
        
        if self.shift_pressed: mod |= KEY_MOD_LSHIFT
        if self.ctrl_pressed: mod |= KEY_MOD_LCTRL
        if self.alt_pressed: mod |= KEY_MOD_LALT

        # Map key
        if key in HID_MAP:
            hid_code = HID_MAP[key]
            self.bt.send_keyboard_report(mod, [hid_code])
        elif key == 'A-LOCK':
            pass # Caps lock logic todo

    def on_key_release(self, key):
        # For regular keys, send "0" (release all) immediately after press for typing feel
        # unless it's a modifier
        if key in ['SHIFT', 'CTRL', 'ALT']:
            if key == 'SHIFT': self.shift_pressed = False
            elif key == 'CTRL': self.ctrl_pressed = False
            elif key == 'ALT': self.alt_pressed = False
            # Send update with no keys but updated modifiers
            # (Simplification: just release everything for now to prevent stuck keys)
            self.bt.send_keyboard_report(0, [])
        else:
            self.bt.send_keyboard_report(0, [])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RPi 5 Bluetooth HID Controller")
        self.setGeometry(0, 0, 800, 480) # Default RPi touchscreen size
        
        # Start BT Service
        self.bt_service = BluetoothHIDService()
        self.bt_service.daemon = True
        self.bt_service.start()
        
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Status Bar
        self.status_label = QLabel("Initializing Bluetooth...")
        self.status_label.setStyleSheet("background-color: #222; color: #0f0; padding: 5px;")
        main_layout.addWidget(self.status_label)
        
        # Touchpad (Top half)
        self.touchpad = TouchPad(self.bt_service)
        main_layout.addWidget(self.touchpad, stretch=1)
        
        # Keyboard (Bottom half)
        self.keyboard = VirtualKeyboard(self.bt_service)
        main_layout.addWidget(self.keyboard, stretch=1)

        # Status Update Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)

    def update_status(self):
        if self.bt_service.connected:
            self.status_label.setText(f"Connected to Device")
            self.status_label.setStyleSheet("background-color: #005500; color: white; padding: 5px;")
        else:
            self.status_label.setText("Waiting for connection... (Pair this device from your PC/Phone)")
            self.status_label.setStyleSheet("background-color: #550000; color: white; padding: 5px;")

    def closeEvent(self, event):
        self.bt_service.running = False
        super().closeEvent(event)

if __name__ == '__main__':
    # Enable Touch Events in Qt
    os.environ["QT_QPA_PLATFORM"] = "xcb" # Or "linuxfb" if no desktop env
    
    app = QApplication(sys.argv)
    window = MainWindow()
    
    # Fullscreen for real use
    # window.showFullScreen() 
    window.show()
    
    sys.exit(app.exec())