import sys
import os
import socket
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import threading
import time
import select
import struct
import signal
import math
import subprocess  # [FIX] Added for hciconfig commands

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QGridLayout, QStackedLayout, QSizePolicy)
from PyQt6.QtCore import Qt, QEvent, QPointF, pyqtSignal, QTimer, QPoint
from PyQt6.QtGui import QFont, QColor, QPalette, QTouchEvent

# ==========================================
# 0. System Constants
# ==========================================
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_MEDIUM = 2
BT_SECURITY_HIGH = 3

# ==========================================
# 1. Bluetooth HID Constants & Descriptors
# ==========================================

HID_REPORT_DESC = "05010906a1018501050719e029e71500250175019508810295017508810395067508150025650507190029658100c005010902a10185020901a1000509190129031500250195037501810295017505810305010930093109381581257f750895038106c0c0"

sdp_record_xml = f"""<?xml version="1.0" encoding="UTF-8" ?>
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
  <attribute id="0x0202">
    <uint8 value="0x80" />
  </attribute>
  <attribute id="0x0205">
    <boolean value="true" />
  </attribute>
  <attribute id="0x0206">
    <sequence>
      <sequence>
        <uint8 value="0x22" />
        <text value="{HID_REPORT_DESC}" encoding="hex" />
      </sequence>
    </sequence>
  </attribute>
</record>
"""

BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"
BLUEZ_PROFILE_MGR_IFACE = "org.bluez.ProfileManager1"
BLUEZ_PROFILE_IFACE = "org.bluez.Profile1"
BLUEZ_AGENT_MGR_IFACE = "org.bluez.AgentManager1"
BLUEZ_AGENT_IFACE = "org.bluez.Agent1"
BLUEZ_ADAPTER_IFACE = "org.bluez.Adapter1"
BLUEZ_DEVICE_IFACE = "org.bluez.Device1"

KEY_MOD_LCTRL = 0x01
KEY_MOD_LSHIFT = 0x02
KEY_MOD_LALT = 0x04
KEY_MOD_LMETA = 0x08

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
# 2. Bluetooth Agent
# ==========================================

class AuthAgent(dbus.service.Object):
    def __init__(self, bus, path):
        dbus.service.Object.__init__(self, bus, path)
        self.bus = bus

    def set_trusted(self, path):
        try:
            props = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, path), DBUS_PROP_IFACE)
            props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))
            print(f"Agent: Set Trusted=True for {path}", flush=True)
        except Exception as e:
            print(f"Agent Trust Error: {e}", flush=True)

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="", out_signature="")
    def Release(self): pass

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        self.set_trusted(device)
        return

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        self.set_trusted(device)
        return "0000"

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        self.set_trusted(device)
        return

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        self.set_trusted(device)
        return

    @dbus.service.method(BLUEZ_AGENT_IFACE, in_signature="", out_signature="")
    def Cancel(self): pass

# ==========================================
# 3. Bluetooth Profile (HID)
# ==========================================

class BTProfile(dbus.service.Object):
    def __init__(self, bus, path, service_ref):
        dbus.service.Object.__init__(self, bus, path)
        self.service = service_ref

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="", out_signature="")
    def Release(self): pass

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="", out_signature="")
    def Cancel(self): pass

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="oha{sv}", out_signature="")
    def NewConnection(self, path, fd, properties):
        print(f"DEBUG: NewConnection from {path}", flush=True)
        self.service.handle_new_connection(fd.take())

    @dbus.service.method(BLUEZ_PROFILE_IFACE, in_signature="o", out_signature="")
    def RequestDisconnection(self, path):
        print(f"DEBUG: RequestDisconnection {path}", flush=True)
        self.service.handle_disconnection()

# ==========================================
# 4. Main Service Logic
# ==========================================

class BluetoothHIDService(threading.Thread):
    def __init__(self):
        super().__init__()
        self.c_socket = None
        self.i_socket = None
        self.running = True
        self.connected = False
        self.os_connected = False
        self.loop = None
        self.manager = None
        self.profile_path = "/org/bluez/hci0/hid_profile"
        self.agent_path = "/org/bluez/AutoAgent"
        self.connected_device_path = None
        
        self.server_c = None
        self.server_i = None

    def force_adapter_config(self):
        """Force configuration of HCI adapter using system calls"""
        print("Forcing HCI Adapter Configuration...", flush=True)
        # Reset and set class to Keyboard/Mouse (0x0025C0)
        cmds = [
            ["sudo", "hciconfig", "hci0", "up"],
            ["sudo", "hciconfig", "hci0", "class", "0x0025C0"],
            ["sudo", "hciconfig", "hci0", "sspmode", "1"],
            ["sudo", "hciconfig", "hci0", "piscan"]
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print(f"HCI Config Error ({cmd}): {e}", flush=True)

    def setup_sockets(self):
        try:
            self.server_c = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            self.server_i = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
            
            self.server_c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_i.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                self.server_c.setsockopt(SOL_BLUETOOTH, BT_SECURITY, BT_SECURITY_MEDIUM)
                self.server_i.setsockopt(SOL_BLUETOOTH, BT_SECURITY, BT_SECURITY_MEDIUM)
            except Exception as e:
                print(f"Warning: Failed to set socket security: {e}", flush=True)

            print("Binding to L2CAP ports 17 (Control) and 19 (Interrupt)...", flush=True)
            self.server_c.bind((socket.BDADDR_ANY, 17))
            self.server_i.bind((socket.BDADDR_ANY, 19))
            
            self.server_c.listen(5)
            self.server_i.listen(5)
            return True
        except Exception as e:
            print(f"CRITICAL: Socket Bind Error: {e}", flush=True)
            return False

    def run(self):
        print("Starting Bluetooth Service...", flush=True)
        
        # [FIX] Force adapter config via shell commands to ensure Class of Device is correct
        self.force_adapter_config()

        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SystemBus()

        self.bus.add_signal_receiver(
            self.device_property_changed,
            bus_name="org.bluez",
            signal_name="PropertiesChanged",
            path_keyword="path"
        )

        try:
            adapter_path = "/org/bluez/hci0"
            adapter = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, adapter_path), DBUS_PROP_IFACE)
            print("Configuring Adapter (Discoverable/Pairable)...", flush=True)
            adapter.Set(BLUEZ_ADAPTER_IFACE, "Powered", dbus.Boolean(True))
            adapter.Set(BLUEZ_ADAPTER_IFACE, "Discoverable", dbus.Boolean(True))
            adapter.Set(BLUEZ_ADAPTER_IFACE, "Pairable", dbus.Boolean(True))
            adapter.Set(BLUEZ_ADAPTER_IFACE, "Alias", "RPi5-Touch-HID")
        except Exception as e:
            print(f"Adapter Config Error: {e}", flush=True)

        if not self.setup_sockets():
            return

        try:
            self.agent = AuthAgent(self.bus, self.agent_path)
            self.agent_mgr = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez"), BLUEZ_AGENT_MGR_IFACE)
            try: self.agent_mgr.UnregisterAgent(self.agent_path)
            except: pass
            self.agent_mgr.RegisterAgent(self.agent_path, "NoInputNoOutput")
            self.agent_mgr.RequestDefaultAgent(self.agent_path)
        except Exception as e:
            print(f"Agent Error: {e}", flush=True)

        self.profile = BTProfile(self.bus, self.profile_path, self)
        self.manager = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez"), BLUEZ_PROFILE_MGR_IFACE)
        
        opts = {
            "ServiceRecord": sdp_record_xml,
            "Role": "server",
            "RequireAuthentication": dbus.Boolean(True),
            "RequireAuthorization": dbus.Boolean(True),
            "AutoConnect": dbus.Boolean(True)
        }
        
        try:
            try: self.manager.UnregisterProfile(self.profile_path)
            except: pass
            self.manager.RegisterProfile(self.profile_path, "00001124-0000-1000-8000-00805f9b34fb", opts)
            print("HID Profile Registered.", flush=True)
        except Exception as e:
            print(f"Failed to register profile: {e}", flush=True)
            return
        
        self.socket_thread = threading.Thread(target=self.listen_sockets_loop, daemon=True)
        self.socket_thread.start()

        self.loop = GLib.MainLoop()
        try: self.loop.run()
        except: pass

    def device_property_changed(self, interface, changed, invalidated, path):
        if interface != "org.bluez.Device1":
            return
        if "Connected" in changed:
            is_connected = changed["Connected"]
            self.os_connected = is_connected
            if is_connected:
                self.connected_device_path = path
            else:
                if self.connected_device_path == path:
                    self.connected_device_path = None

    def listen_sockets_loop(self):
        while self.running:
            if not self.connected:
                try:
                    r, _, _ = select.select([self.server_c, self.server_i], [], [], 1.0)
                    for s in r:
                        client, addr = s.accept()
                        print(f"Accepted connection from {addr}", flush=True)
                        if s is self.server_c:
                            if self.c_socket: self.c_socket.close()
                            self.c_socket = client
                        elif s is self.server_i:
                            if self.i_socket: self.i_socket.close()
                            self.i_socket = client
                    if self.c_socket and self.i_socket:
                        print(">>> Both Channels Connected! <<<", flush=True)
                        self.connected = True
                except Exception: pass
            else:
                try:
                    r, _, x = select.select([self.c_socket, self.i_socket], [], [self.c_socket, self.i_socket], 1.0)
                    if x:
                        self.close_connection()
                        continue
                    for s in r:
                        data = s.recv(1024)
                        if not data:
                            self.close_connection()
                            break
                except Exception:
                    self.close_connection()

    def handle_new_connection(self, fd_int):
        os.close(fd_int)

    def handle_disconnection(self):
        print("BlueZ requested disconnection.", flush=True)
        self.close_connection()

    def close_connection(self):
        if not self.connected: return
        self.connected = False
        print("Closing Connections...", flush=True)
        try:
            if self.c_socket: 
                self.c_socket.shutdown(socket.SHUT_RDWR)
                self.c_socket.close()
            if self.i_socket: 
                self.i_socket.shutdown(socket.SHUT_RDWR)
                self.i_socket.close()
        except: pass
        self.c_socket = None
        self.i_socket = None

    def force_disconnect_device(self):
        self.close_connection()
        if self.connected_device_path:
            print(f"Force disconnecting device: {self.connected_device_path}", flush=True)
            try:
                device = dbus.Interface(self.bus.get_object(BLUEZ_SERVICE_NAME, self.connected_device_path), BLUEZ_DEVICE_IFACE)
                device.Disconnect()
            except Exception as e:
                print(f"Failed to disconnect via DBus: {e}", flush=True)

    def send_keyboard_report(self, modifier, keys):
        if not self.connected or not self.i_socket: return
        report = bytes([0xA1, 0x01, modifier, 0x00] + keys + [0x00] * (6 - len(keys)))
        try: self.i_socket.send(report)
        except: self.close_connection()

    def send_mouse_report(self, buttons, x, y, wheel=0):
        if not self.connected or not self.i_socket: return
        x = max(-127, min(127, x))
        y = max(-127, min(127, y))
        report = bytes([0xA1, 0x02, buttons, x & 0xff, y & 0xff, wheel & 0xff])
        try: self.i_socket.send(report)
        except: self.close_connection()
    
    def stop(self):
        self.running = False
        self.force_disconnect_device()
        try: self.manager.UnregisterProfile(self.profile_path)
        except: pass
        try: self.agent_mgr.UnregisterAgent(self.agent_path)
        except: pass
        if self.loop: self.loop.quit()

# ==========================================
# 5. UI Widgets (Frontend - Hybrid Keyboard)
# ==========================================

class VirtualKeyboard(QWidget):
    def __init__(self, bt_service):
        super().__init__()
        self.bt = bt_service
        self.layout = QGridLayout()
        self.layout.setSpacing(5)
        self.layout.setContentsMargins(5, 5, 5, 5)
        self.setLayout(self.layout)
        
        self.setAttribute(Qt.WidgetAttribute.WA_AcceptTouchEvents, True)
        self.setMouseTracking(True)
        
        self.touch_start_pos = QPointF()
        self.touch_last_pos = QPointF()
        self.active_button = None 
        self.is_dragging = False
        self.drag_threshold = 20
        self.is_scrolling = False
        
        # Status label
        self.status_label = QLabel("Wait", self)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("background-color: #330000; color: #ffcccc; border-radius: 5px; font-size: 14px; font-weight: bold; border: 1px solid #440000;")
        self.status_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        keys = [['ESC', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'BACK'],
                ['TAB', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '\\'],
                ['A-LOCK', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', 'ENTER'],
                ['SHIFT', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'SHIFT'],
                ['CTRL', 'WIN', 'ALT', 'SPACE', 'LEFT', 'UP', 'DOWN', 'RIGHT', 'STATUS']]
        
        self.shift_pressed = False
        self.ctrl_pressed = False
        self.alt_pressed = False
        
        self.buttons = {} 

        self.btn_style_normal = """
            QPushButton {
                background-color: #2d2d2d; 
                color: #e0e0e0; 
                border: 1px solid #3d3d3d; 
                border-radius: 8px; 
                font-size: 20px; 
                font-weight: bold;
            }
        """
        self.btn_style_pressed = """
            QPushButton {
                background-color: #005a9e;
                color: white;
                border: 1px solid #0078d7;
                border-radius: 8px; 
                font-size: 20px; 
                font-weight: bold;
            }
        """
        
        for r, key_row in enumerate(keys):
            self.layout.setRowStretch(r, 1) 
            col = 0
            for key_char in key_row:
                span = 1
                if key_char == 'SPACE': span = 4 
                elif key_char == 'STATUS': span = 1 

                if key_char == 'STATUS':
                    self.layout.addWidget(self.status_label, r, col, 1, span)
                else:
                    btn = QPushButton(key_char)
                    btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
                    btn.setStyleSheet(self.btn_style_normal)
                    btn.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
                    btn.setFocusPolicy(Qt.FocusPolicy.NoFocus) 
                    self.layout.addWidget(btn, r, col, 1, span)
                    self.buttons[btn] = key_char
                
                col += span

    def get_button_at(self, pos):
        for btn in self.buttons.keys():
            if btn.geometry().contains(pos):
                return btn
        return None

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            local_pos = event.position().toPoint()
            
            if self.status_label.geometry().contains(local_pos):
                if self.bt.connected or self.bt.os_connected:
                    self.bt.force_disconnect_device()
                return 

            self.touch_start_pos = event.position()
            self.touch_last_pos = event.position()
            self.is_dragging = False
            self.is_scrolling = False
            self.active_button = None
            
            btn = self.get_button_at(local_pos)
            if btn:
                self.active_button = btn
                btn.setStyleSheet(self.btn_style_pressed)

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.MouseButton.LeftButton:
            curr_pos = event.position()
            dist = (curr_pos - self.touch_start_pos).manhattanLength()
            
            if not self.is_dragging and dist > self.drag_threshold:
                self.is_dragging = True
                if self.active_button:
                    self.active_button.setStyleSheet(self.btn_style_normal)
                    self.active_button = None
            
            if self.is_dragging:
                dx = int((curr_pos.x() - self.touch_last_pos.x()) * 2.0)
                dy = int((curr_pos.y() - self.touch_last_pos.y()) * 2.0)
                if abs(dx) > 0 or abs(dy) > 0:
                    self.bt.send_mouse_report(0, dx, dy, 0)
            
            self.touch_last_pos = curr_pos

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if not self.is_dragging and self.active_button:
                key_char = self.buttons[self.active_button]
                self.on_key_click(key_char)
                self.active_button.setStyleSheet(self.btn_style_normal)
            
            self.is_dragging = False
            self.active_button = None

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        if delta != 0:
            scroll_amount = 1 if delta > 0 else -1
            self.bt.send_mouse_report(0, 0, 0, scroll_amount)

    def event(self, event):
        if event.type() in [QEvent.Type.TouchBegin, QEvent.Type.TouchUpdate, QEvent.Type.TouchEnd]:
            self.handle_touch(event)
            return True
        return super().event(event)

    def handle_touch(self, event):
        points = event.touchPoints()
        if not points: return

        if event.type() == QEvent.Type.TouchBegin:
            self.touch_start_pos = points[0].position()
            self.touch_last_pos = points[0].position()
            self.is_dragging = False
            self.is_scrolling = False
            self.active_button = None
            
            local_pos = points[0].position().toPoint()
            
            if self.status_label.geometry().contains(local_pos):
                if self.bt.connected or self.bt.os_connected:
                    self.bt.force_disconnect_device()
                return

            if len(points) == 2:
                self.is_scrolling = True
            elif len(points) == 1:
                btn = self.get_button_at(local_pos)
                if btn:
                    self.active_button = btn
                    btn.setStyleSheet(self.btn_style_pressed)

        elif event.type() == QEvent.Type.TouchUpdate:
            curr_pos = points[0].position()
            dist = (curr_pos - self.touch_start_pos).manhattanLength()
            
            if not self.is_dragging and dist > self.drag_threshold:
                self.is_dragging = True
                if self.active_button:
                    self.active_button.setStyleSheet(self.btn_style_normal)
                    self.active_button = None
            
            if self.is_dragging:
                if self.is_scrolling and len(points) >= 1:
                    dy = int((curr_pos.y() - self.touch_last_pos.y()) * 0.5)
                    if abs(dy) > 0:
                        self.bt.send_mouse_report(0, 0, 0, dy)
                else:
                    dx = int((curr_pos.x() - self.touch_last_pos.x()) * 2.0)
                    dy = int((curr_pos.y() - self.touch_last_pos.y()) * 2.0)
                    if abs(dx) > 0 or abs(dy) > 0:
                        self.bt.send_mouse_report(0, dx, dy, 0)
            
            self.touch_last_pos = curr_pos

        elif event.type() == QEvent.Type.TouchEnd:
            if not self.is_dragging and self.active_button:
                key_char = self.buttons[self.active_button]
                self.on_key_click(key_char)
                self.active_button.setStyleSheet(self.btn_style_normal)
            
            self.is_dragging = False
            self.active_button = None

    # [FIX] Simplified status text to prevent layout shift
    def update_status(self, connected, os_connected):
        if connected:
            self.status_label.setText("Active")
            self.status_label.setStyleSheet("background-color: #004d00; color: #ccffcc; border-radius: 5px; font-size: 14px; font-weight: bold; border: 1px solid #006600;")
        elif os_connected:
            self.status_label.setText("Paired")
            self.status_label.setStyleSheet("background-color: #663300; color: #ffcc99; border-radius: 5px; font-size: 14px; font-weight: bold; border: 1px solid #884400;")
        else:
            self.status_label.setText("Wait")
            self.status_label.setStyleSheet("background-color: #550000; color: #ffcccc; border-radius: 5px; font-size: 14px; font-weight: bold; border: 1px solid #440000;")

    def on_key_click(self, key):
        self.on_key_press(key)
        self.on_key_release(key)

    def on_key_press(self, key):
        mod = 0
        if key == 'SHIFT': self.shift_pressed = not self.shift_pressed
        elif key == 'CTRL': self.ctrl_pressed = not self.ctrl_pressed
        elif key == 'ALT': self.alt_pressed = not self.alt_pressed
        
        if self.shift_pressed: mod |= KEY_MOD_LSHIFT
        if self.ctrl_pressed: mod |= KEY_MOD_LCTRL
        if self.alt_pressed: mod |= KEY_MOD_LALT
        
        if key in HID_MAP:
            self.bt.send_keyboard_report(mod, [HID_MAP[key]])

    def on_key_release(self, key):
        mod = 0
        if self.shift_pressed: mod |= KEY_MOD_LSHIFT
        if self.ctrl_pressed: mod |= KEY_MOD_LCTRL
        if self.alt_pressed: mod |= KEY_MOD_LALT
        self.bt.send_keyboard_report(mod, [])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RPi 5 Bluetooth HID Controller")
        
        screen = QApplication.primaryScreen()
        rect = screen.availableGeometry()
        self.setGeometry(rect)
        self.setStyleSheet("background-color: #000000;")
        
        self.bt_service = BluetoothHIDService()
        self.bt_service.daemon = True
        self.bt_service.start()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Only Keyboard (Touchpad integrated)
        self.keyboard = VirtualKeyboard(self.bt_service)
        main_layout.addWidget(self.keyboard)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)

    def update_status(self):
        self.keyboard.update_status(self.bt_service.connected, self.bt_service.os_connected)

    def closeEvent(self, event):
        print("Closing Application...", flush=True)
        self.bt_service.stop()
        super().closeEvent(event)

# Ctrl+C Handler
def signal_handler(sig, frame):
    print("Ctrl+C caught. Exiting...", flush=True)
    QApplication.closeAllWindows()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    
    os.environ["QT_QPA_PLATFORM"] = "xcb"
    app = QApplication(sys.argv)
    
    signal_timer = QTimer()
    signal_timer.start(500)
    signal_timer.timeout.connect(lambda: None)
    
    window = MainWindow()
    window.showFullScreen()
    sys.exit(app.exec())