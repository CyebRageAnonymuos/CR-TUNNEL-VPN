#!/usr/bin/env python3

import base64
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zipfile

try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gtk, Gdk, GLib, Pango, cairo
except Exception:
    print("GTK3 is required. Install it with: sudo apt install python3-gi gir1.2-gtk-3.0")
    sys.exit(1)

APP_NAME = "CR Tunnel"
CONFIG_DIR = os.path.expanduser("~/.config/crtunnel")
DATA_DIR = os.path.expanduser("~/.local/share/crtunnel")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
XRAY_BIN = os.path.join(DATA_DIR, "xray")
SOCKS_PORT = 10808
HTTP_PORT = 10809

ACCENT = "#00E5FF"
ACCENT_PURPLE = "#A855F7"
BG_DARK = "#05070F"

XRAY_RELEASE_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-{}.zip"

DEFAULT_CONFIG = {
    "subscriptions": [],
    "servers": [],
    "groups": {},
    "auto_connect": False,
    "mode": "socks",
    "dns": "1.1.1.1",
    "mux": False,
    "auto_update_subs": False,
    "auto_update_interval_hours": 6,
    "selected_group": "",
    "selected_guid": ""
}


def ensure_dirs():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)


def load_config():
    ensure_dirs()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(cfg)
            return merged
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    ensure_dirs()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def arch_name():
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "64"
    if m in ("aarch64", "arm64"):
        return "arm64-v8a"
    if m in ("armv7l", "armv6l"):
        return "arm32-v7a"
    return "64"


def download_xray(progress_cb=None):
    if os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return True, None
    url = XRAY_RELEASE_URL.format(arch_name())
    zip_path = os.path.join(DATA_DIR, "xray.zip")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "crtunnel"})
        with urllib.request.urlopen(req) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done = 0
            with open(zip_path, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    if progress_cb and total:
                        GLib.idle_add(progress_cb, done / total)
        with zipfile.ZipFile(zip_path) as z:
            for name in z.namelist():
                if name.endswith("xray"):
                    with open(XRAY_BIN, "wb") as out:
                        out.write(z.read(name))
                    break
        os.chmod(XRAY_BIN, 0o755)
        os.remove(zip_path)
        return True, None
    except Exception as e:
        return False, str(e)


def decode_b64_pad(s):
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_vless(uri, remark):
    info = uri.netloc
    uuid, addr = info.split("@", 1) if "@" in info else ("", info)
    host, port = addr, 443
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    q = urllib.parse.parse_qs(uri.query)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    stream = {}
    net = params.get("type", "tcp")
    stream["network"] = net
    stream["security"] = params.get("security", "none")
    if params.get("sni"):
        stream["sni"] = params["sni"]
    if params.get("fp"):
        stream["fingerprint"] = params["fp"]
    if net in ("ws", "http"):
        ws = {}
        if params.get("path"):
            ws["path"] = params["path"]
        if params.get("host"):
            ws["headers"] = {"Host": params["host"]}
        stream[net + "Settings"] = ws
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", params.get("path", "")),
            "multiMode": params.get("mode", "gun") == "multi"
        }
    elif net == "xhttp":
        xh = {
            "path": params.get("path", "/"),
            "host": [params.get("host", "")] if params.get("host") else []
        }
        mode = params.get("mode", "auto")
        if mode in ("stream-up", "packet-up", "auto"):
            xh["mode"] = mode
        stream["xhttpSettings"] = xh
    if params.get("pbk"):
        stream["realitySettings"] = {
            "serverName": params.get("sni", ""),
            "fingerprint": params.get("fp", "chrome"),
            "publicKey": params["pbk"],
            "shortId": params.get("sid", ""),
            "spiderX": params.get("spx", "/")
        }
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uuid, "encryption": params.get("encryption", "none"), "flow": params.get("flow", "")}]
            }]
        },
        "streamSettings": stream
    }
    return {"remark": remark or "vless", "outbound": outbound}


def parse_trojan(uri, remark):
    info = uri.netloc
    password, addr = info.split("@", 1) if "@" in info else ("", info)
    host, port = addr, 443
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    q = urllib.parse.parse_qs(uri.query)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    stream = {"network": "tcp", "security": "tls"}
    if params.get("sni"):
        stream["sni"] = params["sni"]
    if params.get("fp"):
        stream["fingerprint"] = params["fp"]
    if params.get("type", "tcp") in ("ws", "http", "grpc", "xhttp"):
        net = params["type"]
        stream["network"] = net
        if net in ("ws", "http"):
            ws = {}
            if params.get("path"):
                ws["path"] = params["path"]
            if params.get("host"):
                ws["headers"] = {"Host": params["host"]}
            stream[net + "Settings"] = ws
        elif net == "grpc":
            stream["grpcSettings"] = {
                "serviceName": params.get("serviceName", params.get("path", "")),
                "multiMode": params.get("mode", "gun") == "multi"
            }
        elif net == "xhttp":
            stream["xhttpSettings"] = {
                "path": params.get("path", "/"),
                "host": [params.get("host", "")] if params.get("host") else []
            }
    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": host, "port": port, "password": password, "level": 0}]
        },
        "streamSettings": stream
    }
    return {"remark": remark or "trojan", "outbound": outbound}


def parse_vmess(uri, remark):
    try:
        raw = decode_b64_pad(uri.netloc)
        data = json.loads(raw)
    except Exception:
        return None
    stream = {"network": data.get("net", "tcp"), "security": data.get("tls", "none")}
    if data.get("sni"):
        stream["sni"] = data["sni"]
    if data.get("fp"):
        stream["fingerprint"] = data["fp"]
    net = data.get("net")
    if net == "ws":
        stream["wsSettings"] = {"path": data.get("path", ""), "headers": {"Host": data.get("host", "")}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", ""), "multiMode": False}
    elif net == "http":
        stream["httpSettings"] = {"path": data.get("path", ""), "host": [data.get("host", "")]}
    elif net == "xhttp":
        stream["xhttpSettings"] = {
            "path": data.get("path", "/"),
            "host": [data.get("host", "")] if data.get("host") else []
        }
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "users": [{
                    "id": data.get("id", ""),
                    "alterId": int(data.get("aid", 0)),
                    "security": data.get("scy", "auto")
                }]
            }]
        },
        "streamSettings": stream
    }
    return {"remark": remark or data.get("ps", "vmess"), "outbound": outbound}


def parse_ss(uri, remark):
    info = uri.netloc
    host, port, method, password = "", 443, "", ""
    if "@" in info:
        head, addr = info.split("@", 1)
        host, port = addr, 443
        if ":" in addr:
            h, p = addr.rsplit(":", 1)
            if p.isdigit():
                host, port = h, int(p)
        dec = decode_b64_pad(head)
        if ":" in dec:
            method, password = dec.split(":", 1)
    else:
        dec = decode_b64_pad(info)
        if ":" in dec:
            method, password = dec.split(":", 1)
    if not method or not password:
        return None
    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password}]},
        "streamSettings": {"network": "tcp", "security": "none"}
    }
    return {"remark": remark or "ss", "outbound": outbound}


def parse_socks(uri, remark):
    info = uri.netloc
    user, addr = "", info
    if "@" in info:
        user, addr = info.split("@", 1)
    host, port = addr, 1080
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    outbound = {
        "protocol": "socks",
        "settings": {
            "servers": [{"address": host, "port": port}]
        },
        "streamSettings": {"network": "tcp", "security": "none"}
    }
    return {"remark": remark or "socks", "outbound": outbound}


def parse_hy2(uri, remark):
    info = uri.netloc
    auth, addr = info.split("@", 1) if "@" in info else ("", info)
    host, port = addr, 443
    if ":" in addr:
        h, p = addr.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    q = urllib.parse.parse_qs(uri.query)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    outbound = {
        "protocol": "hysteria2",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "auth": auth,
                "tls": {
                    "sni": params.get("sni", host),
                    "insecure": params.get("insecure", "0") in ("1", "true")
                }
            }]
        },
        "streamSettings": {"network": "tcp", "security": "tls"}
    }
    return {"remark": remark or "hy2", "outbound": outbound}


def parse_link(raw_link):
    link = raw_link.strip()
    if not link:
        return None
    if link.startswith("vmess://"):
        return parse_vmess(urllib.parse.urlparse(link), "")
    if link.startswith("vless://"):
        return parse_vless(urllib.parse.urlparse(link), "")
    if link.startswith("trojan://"):
        return parse_trojan(urllib.parse.urlparse(link), "")
    if link.startswith("ss://"):
        return parse_ss(urllib.parse.urlparse(link), "")
    if link.startswith("socks://"):
        return parse_socks(urllib.parse.urlparse(link), "")
    if link.startswith("hy2://"):
        return parse_hy2(urllib.parse.urlparse(link), "")
    return None


def fetch_subscription(url):
    req = urllib.request.Request(url, headers={"User-Agent": "crtunnel"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()
    text = content.decode("utf-8", errors="replace")
    if text.startswith("{"):
        try:
            data = json.loads(text)
            text = data.get("data", "")
        except Exception:
            pass
    if text.startswith(("vless://", "vmess://", "ss://", "trojan://", "socks://", "hy2://")):
        return text.splitlines()
    try:
        decoded = decode_b64_pad(text.replace("\n", ""))
        if decoded:
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            if any(l.startswith(("vless://", "vmess://", "ss://", "trojan://", "socks://", "hy2://")) for l in lines):
                return lines
    except Exception:
        pass
    return text.splitlines()


def tcp_ping(host, port, timeout=4.0):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return (time.time() - start) * 1000
    except Exception:
        return None


def server_guid(srv):
    return json.dumps(srv["outbound"], sort_keys=True)


class TunnelManager:
    def __init__(self):
        self.process = None
        self.config_path = os.path.join(CONFIG_DIR, "xray-config.json")
        self.status = "stopped"

    def build_config(self, server, mode, dns="1.1.1.1", mux=False):
        inbounds = [
            {
                "tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT,
                "protocol": "socks", "settings": {"auth": "noauth", "udp": True}
            },
            {
                "tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT,
                "protocol": "http", "settings": {"allowTransparent": False}
            }
        ]
        if mode == "tun":
            inbounds.insert(0, {
                "tag": "tun-in", "protocol": "tun",
                "settings": {"address": ["10.0.0.1", "fd00::1"], "mtu": 1500,
                             "autoRoute": True, "strictRoute": False},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            })
        outbound = json.loads(json.dumps(server["outbound"]))
        outbound["tag"] = "proxy"
        if mux and outbound["protocol"] in ("vless", "vmess", "trojan"):
            outbound["mux"] = {"enabled": True, "concurrency": 8}
        cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "dns": {
                "servers": [{"address": dns, "queryStrategy": "UseIP"}],
                "queryStrategy": "UseIP"
            }
        }
        return cfg

    def start(self, server, mode, dns, mux=False):
        self.stop()
        cfg = self.build_config(server, mode, dns, mux)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        self.process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", self.config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.status = "running"

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
        self.process = None
        self.status = "stopped"


class CircleArea(Gtk.DrawingArea):
    def __init__(self, app, size=210):
        super().__init__()
        self.app = app
        self.set_size_request(size, size)
        self.set_can_focus(True)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.connect("draw", self.on_draw)
        self.connect("button-press-event", self.on_click)
        self.pulse = 0.0
        self.pulse_dir = 1

    def on_click(self, widget, event):
        if event.button == 1:
            self.app.on_connect_clicked()
        return True

    def on_draw(self, widget, cr):
        w = widget.get_allocated_width()
        h = widget.get_allocated_height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 14
        running = self.app.tunnel.status == "running"

        cr.set_source_rgba(0.02, 0.03, 0.08, 0.9)
        cr.arc(cx, cy, radius, 0, 2 * 3.14159)
        cr.fill()

        glow_r = radius + 8
        for i in range(3):
            alpha = 0.12 - i * 0.03
            cr.set_source_rgba(0, 0.9, 1.0, alpha)
            cr.arc(cx, cy, glow_r - i * 3, 0, 2 * 3.14159)
            cr.set_line_width(2)
            cr.stroke()

        ring_start = 0.0
        ring_end = 2 * 3.14159
        if running:
            self.pulse += 0.02 * self.pulse_dir
            if self.pulse > 1.0 or self.pulse < 0.0:
                self.pulse_dir *= -1
        ring_color = (0, 0.9, 1.0) if not running else (0.0, 0.95, 0.55)
        for i in range(40):
            a = ring_start + (ring_end - ring_start) * i / 40
            a2 = ring_start + (ring_end - ring_start) * (i + 1) / 40
            cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 0.4 + 0.6 * (i % 4) / 4)
            cr.arc(cx, cy, radius - 6, a, a2)
            cr.set_line_width(6)
            cr.stroke()

        cr.set_source_rgba(ring_color[0], ring_color[1], ring_color[2], 1.0)
        cr.arc(cx, cy, radius - 12, 0, 2 * 3.14159)
        cr.set_line_width(1.5)
        cr.stroke()

        if running:
            cr.set_source_rgba(0.0, 0.95, 0.55, 1.0)
            cr.arc(cx, cy, 16, 0, 2 * 3.14159)
            cr.fill()
            cr.set_source_rgba(0.02, 0.03, 0.08, 1.0)
            cr.rectangle(cx - 5, cy - 8, 4, 16)
            cr.rectangle(cx + 2, cy - 8, 4, 16)
            cr.fill()
        else:
            cr.set_source_rgba(0.0, 0.9, 1.0, 1.0)
            cr.move_to(cx - 6, cy - 12)
            cr.line_to(cx - 6, cy + 12)
            cr.line_to(cx + 12, cy)
            cr.close_path()
            cr.fill()
        return False


class App(Gtk.Window):
    def __init__(self):
        super().__init__(title=APP_NAME)
        self.set_default_size(500, 720)
        self.config = load_config()
        self.tunnel = TunnelManager()
        self.servers = self.config.get("servers", [])
        self.selected = None
        self.testing = False
        self.auto_optimizing = False
        self._build_ui()
        self._apply_style()
        self._populate_groups()
        self.connect("destroy", self.on_close)
        self.connect("delete-event", self.on_delete)
        signal.signal(signal.SIGINT, self._sigint)
        if self.config.get("auto_update_subs"):
            self._schedule_auto_update()

    def _sigint(self, *args):
        self.tunnel.stop()
        Gtk.main_quit()

    def on_delete(self, widget, event):
        self.tunnel.stop()
        return False

    def on_close(self, widget):
        self.tunnel.stop()

    def _build_ui(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(vbox)

        header = Gtk.HeaderBar()
        header.set_title(APP_NAME)
        header.set_subtitle("Powered by Xray-core")
        header.set_show_close_button(True)
        self.set_titlebar(header)

        settings_btn = Gtk.Button.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.BUTTON)
        settings_btn.connect("clicked", self.on_settings)
        header.pack_end(settings_btn)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        body.set_margin_top(14)
        body.set_margin_bottom(14)
        body.set_margin_start(14)
        body.set_margin_end(14)
        vbox.pack_start(body, True, True, 0)

        self.circle = CircleArea(self)
        body.pack_start(self.circle, False, False, 0)

        self.status_label = Gtk.Label(label="Disconnected")
        self.status_label.get_style_context().add_class("status-off")
        body.pack_start(self.status_label, False, False, 0)

        self.remark_label = Gtk.Label(label="Select a server below")
        self.remark_label.get_style_context().add_class("hint")
        body.pack_start(self.remark_label, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_row.set_margin_top(6)

        self.connect_btn = Gtk.Button(label="Connect")
        self.connect_btn.get_style_context().add_class("primary-btn")
        self.connect_btn.connect("clicked", self.on_connect_clicked)
        btn_row.pack_start(self.connect_btn, True, True, 0)

        test_btn = Gtk.Button(label="Speed Test")
        test_btn.get_style_context().add_class("ghost-btn")
        test_btn.connect("clicked", self.on_speed_test)
        btn_row.pack_start(test_btn, True, True, 0)

        self.optimize_btn = Gtk.Button(label="Auto Optimize")
        self.optimize_btn.get_style_context().add_class("ghost-btn")
        self.optimize_btn.connect("clicked", self.on_auto_optimize)
        btn_row.pack_start(self.optimize_btn, True, True, 0)

        body.pack_start(btn_row, False, False, 0)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        mode_row.pack_start(Gtk.Label(label="Mode:"), False, False, 0)
        self.mode_combo = Gtk.ComboBoxText()
        self.mode_combo.append("socks", "Proxy (SOCKS/HTTP)")
        self.mode_combo.append("tun", "TUN (system-wide, root)")
        self.mode_combo.set_active(0 if self.config.get("mode") == "socks" else 1)
        self.mode_combo.connect("changed", self.on_mode_changed)
        mode_row.pack_start(self.mode_combo, True, True, 0)
        body.pack_start(mode_row, False, False, 0)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        sub_btn = Gtk.Button(label="+ Subscription")
        sub_btn.get_style_context().add_class("ghost-btn")
        sub_btn.connect("clicked", self.on_add_subscription)
        link_btn = Gtk.Button(label="+ Link")
        link_btn.get_style_context().add_class("ghost-btn")
        link_btn.connect("clicked", self.on_add_link)
        file_btn = Gtk.Button(label="+ File")
        file_btn.get_style_context().add_class("ghost-btn")
        file_btn.connect("clicked", self.on_import_file)
        refresh_btn = Gtk.Button(label="Refresh Subs")
        refresh_btn.get_style_context().add_class("ghost-btn")
        refresh_btn.connect("clicked", self.on_refresh_subs)
        toolbar.pack_start(sub_btn, True, True, 0)
        toolbar.pack_start(link_btn, True, True, 0)
        toolbar.pack_start(file_btn, True, True, 0)
        toolbar.pack_start(refresh_btn, True, True, 0)
        body.pack_start(toolbar, False, False, 0)

        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self.notebook.set_show_border(False)
        self.notebook.connect("switch-page", self.on_group_switch)
        body.pack_start(self.notebook, True, True, 0)

        hint = Gtk.Label(label="SOCKS 127.0.0.1:{}   HTTP 127.0.0.1:{}".format(SOCKS_PORT, HTTP_PORT))
        hint.get_style_context().add_class("hint")
        body.pack_start(hint, False, False, 0)

    def _apply_style(self):
        css = """
        @define-color accent #00E5FF;
        @define-color accent2 #A855F7;
        window {
            background: linear-gradient(#05070F, #0A0E27, #0F1530);
        }
        headerbar {
            background: #070B18;
            color: #00E5FF;
            border-bottom: 1px solid #1A2A55;
        }
        headerbar label { color: #00E5FF; font-weight: bold; }
        headerbar subtitle { color: #A855F7; }
        .status-on { color: #00E676; font-size: 18px; font-weight: bold; }
        .status-off { color: #ff5252; font-size: 18px; font-weight: bold; }
        .hint { color: #8899bb; font-size: 12px; }
        .primary-btn {
            background: linear-gradient(#00E5FF, #00B3D6);
            color: #05070F;
            font-weight: bold;
            border-radius: 22px;
            padding: 10px 16px;
        }
        .primary-btn:hover { background: linear-gradient(#33EBFF, #00E5FF); }
        .ghost-btn {
            background: rgba(0, 229, 255, 0.08);
            color: #00E5FF;
            border: 1px solid rgba(0, 229, 255, 0.35);
            border-radius: 22px;
            padding: 10px 16px;
        }
        .ghost-btn:hover { background: rgba(0, 229, 255, 0.16); }
        notebook { background: transparent; }
        notebook header { background: transparent; border: none; }
        notebook tab {
            background: rgba(0, 229, 255, 0.07);
            color: #9fb3d1;
            border-radius: 14px 14px 0 0;
            padding: 8px 18px;
            margin: 2px;
        }
        notebook tab:checked { background: rgba(0, 229, 255, 0.18); color: #00E5FF; }
        .server-list {
            background: rgba(9, 13, 32, 0.6);
            border-radius: 14px;
            border: 1px solid rgba(0, 229, 255, 0.12);
        }
        .server-row {
            background: rgba(0, 229, 255, 0.05);
            border: 1px solid rgba(0, 229, 255, 0.12);
            border-radius: 12px;
            padding: 10px 12px;
            margin: 4px 8px;
        }
        .server-row:hover { background: rgba(0, 229, 255, 0.12); }
        .server-row.selected { background: rgba(168, 85, 247, 0.18); border-color: rgba(168, 85, 247, 0.5); }
        .server-name { color: #e8f6ff; font-weight: bold; font-size: 14px; }
        .server-sub { color: #00E5FF; font-size: 11px; }
        .server-detail { color: #8899bb; font-size: 11px; }
        .ping-good { color: #00E676; font-weight: bold; }
        .ping-mid { color: #FFC107; font-weight: bold; }
        .ping-bad { color: #ff5252; font-weight: bold; }
        .ping-none { color: #556; font-weight: bold; }
        .card {
            background: rgba(11, 17, 42, 0.7);
            border: 1px solid rgba(0, 229, 255, 0.15);
            border-radius: 12px;
            padding: 16px;
        }
        entry, combobox { background: #0B112A; color: #e8f6ff; border: 1px solid rgba(0, 229, 255, 0.3); border-radius: 10px; }
        scrolledwindow { background: transparent; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css.encode())
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def _populate_groups(self):
        for child in self.notebook.get_children():
            self.notebook.remove(child)
        groups = self.config.get("groups", {})
        if not groups:
            groups = {"Default": []}
        self.group_pages = {}
        for gname, guids in groups.items():
            page = self._make_group_page(gname, guids)
            self.notebook.append_page(page, Gtk.Label(label=gname))
            self.group_pages[gname] = page
        sel = self.config.get("selected_group", "Default")
        for i in range(self.notebook.get_n_pages()):
            if self.notebook.get_tab_label_text(self.notebook.get_nth_page(i)) == sel:
                self.notebook.set_current_page(i)
                break

    def _make_group_page(self, gname, guids):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        search = Gtk.SearchEntry()
        search.set_placeholder_text("Search servers...")
        search.connect("search-changed", lambda e: self._filter_servers(e, box))
        box.pack_start(search, False, False, 0)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        listbox = Gtk.ListBox()
        listbox.get_style_context().add_class("server-list")
        listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        listbox.connect("row-selected", self.on_server_selected)
        scroller.add(listbox)
        box.pack_start(scroller, True, True, 0)
        box.gname = gname
        box.guids = guids
        box.listbox = listbox
        box.search = search
        box.filter_text = ""
        self._fill_list(box)
        return box

    def _fill_list(self, page):
        while True:
            row = page.listbox.get_row_at_index(0)
            if row is None:
                break
            page.listbox.remove(row)
        guids = page.guids if page.guids else [s.get("guid", server_guid(s)) for s in self.servers]
        for srv in self.servers:
            g = srv.get("guid", server_guid(srv))
            if g not in guids:
                continue
            filter_txt = page.filter_text.lower()
            if filter_txt and filter_txt not in (srv.get("remark", "") or "").lower():
                continue
            page.listbox.add(ServerRow(srv, self))

    def _filter_servers(self, entry, page_box):
        for page in self.group_pages.values():
            if page == page_box:
                page.filter_text = entry.get_text()
                self._fill_list(page)

    def on_group_switch(self, notebook, page, num):
        gname = notebook.get_tab_label_text(page)
        self.config["selected_group"] = gname
        save_config(self.config)

    def on_server_selected(self, listbox, row):
        if row is not None:
            self.selected = row.server
            self.remark_label.set_text(row.server.get("remark", ""))
            self.config["selected_guid"] = self.selected.get("guid", server_guid(self.selected))
            save_config(self.config)
            self._refresh_selection()

    def _refresh_selection(self):
        for page in self.group_pages.values():
            for i in range(page.listbox.get_children().__len__()):
                row = page.listbox.get_row_at_index(i)
                if row is not None:
                    if row.server == self.selected:
                        row.get_style_context().add_class("selected")
                    else:
                        row.get_style_context().remove_class("selected")

    def on_connect_clicked(self):
        if self.tunnel.status == "running":
            self.tunnel.stop()
            self._set_status(False, "Disconnected")
            return
        if not self.selected:
            self._toast("Select a server first")
            return
        if not os.path.exists(XRAY_BIN):
            self._toast("Xray-core not found. Re-run install.sh")
            return
        mode = self.mode_combo.get_active_id() or "socks"
        if mode == "tun" and os.geteuid() != 0:
            self._toast("TUN mode needs root: sudo crtunnel")
            return
        threading.Thread(
            target=self._connect_worker,
            args=(self.selected, mode),
            daemon=True
        ).start()

    def _connect_worker(self, server, mode):
        try:
            self.tunnel.start(server, mode, self.config.get("dns", "1.1.1.1"), self.config.get("mux", False))
        except Exception as e:
            GLib.idle_add(self._toast, "Connect failed: {}".format(e))
            return
        GLib.idle_add(self._set_status, True, server.get("remark", ""))

    def _set_status(self, running, text):
        self.status_label.set_text("Connected" if running else "Disconnected")
        ctx = self.status_label.get_style_context()
        ctx.remove_class("status-on")
        ctx.remove_class("status-off")
        ctx.add_class("status-on" if running else "status-off")
        self.connect_btn.set_label("Disconnect" if running else "Connect")
        self.remark_label.set_text(text)
        self.circle.queue_draw()

    def on_speed_test(self, btn):
        if self.testing:
            return
        if not self.servers:
            self._toast("No servers to test")
            return
        self.testing = True
        btn.set_label("Testing...")
        threading.Thread(target=self._speed_test_worker, args=(btn,), daemon=True).start()

    def _speed_test_worker(self, btn):
        for srv in self.servers:
            out = srv["outbound"]
            host = out["settings"].get("vnext", [{}])[0].get("address") or \
                   out["settings"].get("servers", [{}])[0].get("address") or ""
            port = out["settings"].get("vnext", [{}])[0].get("port") or \
                   out["settings"].get("servers", [{}])[0].get("port") or 443
            ms = tcp_ping(host, int(port))
            srv["ping"] = int(ms) if ms is not None else None
        self.config["servers"] = self.servers
        save_config(self.config)
        GLib.idle_add(self._speed_test_done, btn)

    def _speed_test_done(self, btn):
        self.testing = False
        btn.set_label("Speed Test")
        for page in self.group_pages.values():
            self._fill_list(page)

    def on_auto_optimize(self, btn):
        if self.auto_optimizing:
            return
        if not self.servers:
            self._toast("No servers to optimize")
            return
        self.auto_optimizing = True
        btn.set_label("Optimizing...")
        threading.Thread(target=self._auto_optimize_worker, args=(btn,), daemon=True).start()

    def _auto_optimize_worker(self, btn):
        best = None
        best_ms = None
        for srv in self.servers:
            out = srv["outbound"]
            host = out["settings"].get("vnext", [{}])[0].get("address") or \
                   out["settings"].get("servers", [{}])[0].get("address") or ""
            port = out["settings"].get("vnext", [{}])[0].get("port") or \
                   out["settings"].get("servers", [{}])[0].get("port") or 443
            ms = tcp_ping(host, int(port))
            srv["ping"] = int(ms) if ms is not None else None
            if ms is not None and (best_ms is None or ms < best_ms):
                best_ms = ms
                best = srv
        self.config["servers"] = self.servers
        save_config(self.config)
        GLib.idle_add(self._auto_optimize_done, btn, best, best_ms)

    def _auto_optimize_done(self, btn, best, best_ms):
        self.auto_optimizing = False
        btn.set_label("Auto Optimize")
        if best is None:
            self._toast("No reachable servers")
            return
        self.selected = best
        self.remark_label.set_text(best.get("remark", ""))
        self._refresh_selection()
        mode = self.mode_combo.get_active_id() or "socks"
        if mode == "tun" and os.geteuid() != 0:
            self._toast("Best server: {} ({} ms). TUN needs root.".format(
                best.get("remark", ""), int(best_ms)))
            return
        threading.Thread(
            target=self._connect_worker,
            args=(best, mode),
            daemon=True
        ).start()
        GLib.idle_add(self._toast, "Connected to best server ({} ms)".format(int(best_ms)))

    def on_mode_changed(self, combo):
        self.config["mode"] = combo.get_active_id() or "socks"
        save_config(self.config)

    def on_settings(self, btn):
        dlg = Gtk.Dialog(title="Settings", transient_for=self)
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        box = dlg.get_content_area()
        grid = Gtk.Grid()
        grid.set_row_spacing(10)
        grid.set_column_spacing(10)
        grid.set_margin_top(14)
        grid.set_margin_bottom(14)
        grid.set_margin_start(14)
        grid.set_margin_end(14)

        row = 0
        grid.attach(Gtk.Label(label="DNS:"), 0, row, 1, 1)
        dns_entry = Gtk.Entry()
        dns_entry.set_text(self.config.get("dns", "1.1.1.1"))
        grid.attach(dns_entry, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Mux:"), 0, row, 1, 1)
        mux_check = Gtk.CheckButton(label="Enable multiplexing")
        mux_check.set_active(self.config.get("mux", False))
        grid.attach(mux_check, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Auto update subs:"), 0, row, 1, 1)
        auto_check = Gtk.CheckButton(label="Update subscriptions periodically")
        auto_check.set_active(self.config.get("auto_update_subs", False))
        grid.attach(auto_check, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Interval (h):"), 0, row, 1, 1)
        interval_spin = Gtk.SpinButton.new_with_range(1, 168, 1)
        interval_spin.set_value(self.config.get("auto_update_interval_hours", 6))
        grid.attach(interval_spin, 1, row, 1, 1)
        row += 1

        grid.attach(Gtk.Label(label="Auto connect:"), 0, row, 1, 1)
        auto_conn = Gtk.CheckButton(label="Connect on launch")
        auto_conn.set_active(self.config.get("auto_connect", False))
        grid.attach(auto_conn, 1, row, 1, 1)
        row += 1

        box.pack_start(grid, False, False, 0)
        dlg.show_all()
        resp = dlg.run()
        if resp == Gtk.ResponseType.OK:
            self.config["dns"] = dns_entry.get_text().strip() or "1.1.1.1"
            self.config["mux"] = mux_check.get_active()
            self.config["auto_update_subs"] = auto_check.get_active()
            self.config["auto_update_interval_hours"] = int(interval_spin.get_value())
            self.config["auto_connect"] = auto_conn.get_active()
            save_config(self.config)
            if self.config["auto_update_subs"]:
                self._schedule_auto_update()
        dlg.destroy()

    def _schedule_auto_update(self):
        def updater():
            while True:
                time.sleep(self.config.get("auto_update_interval_hours", 6) * 3600)
                for url in self.config.get("subscriptions", []):
                    try:
                        self._refresh_sub(url, silent=True)
                    except Exception:
                        pass
        threading.Thread(target=updater, daemon=True).start()

    def on_add_subscription(self, btn):
        dlg = Gtk.Dialog(title="Add Subscription", transient_for=self)
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        entry = Gtk.Entry()
        entry.set_placeholder_text("https://example.com/sub")
        box = dlg.get_content_area()
        box.pack_start(entry, False, False, 0)
        box.set_margin_top(14)
        box.set_margin_bottom(14)
        box.set_margin_start(14)
        box.set_margin_end(14)
        dlg.show_all()
        resp = dlg.run()
        url = entry.get_text().strip()
        dlg.destroy()
        if resp == Gtk.ResponseType.OK and url:
            if url not in self.config.setdefault("subscriptions", []):
                self.config["subscriptions"].append(url)
                save_config(self.config)
            self._refresh_sub(url)

    def _refresh_sub(self, url, silent=False):
        def worker():
            try:
                lines = fetch_subscription(url)
                parsed = []
                for line in lines:
                    srv = parse_link(line)
                    if srv:
                        srv["guid"] = server_guid(srv)
                        parsed.append(srv)
                if parsed:
                    existing = {s["guid"] for s in self.servers}
                    added = 0
                    for srv in parsed:
                        if srv["guid"] not in existing:
                            self.servers.append(srv)
                            existing.add(srv["guid"])
                            added += 1
                    self.config["servers"] = self.servers
                    if not self.config.get("groups"):
                        self.config["groups"] = {"Default": [s["guid"] for s in self.servers]}
                    save_config(self.config)
                    GLib.idle_add(self._servers_changed)
                    if not silent:
                        GLib.idle_add(self._toast, "Added {} new servers".format(added))
                elif not silent:
                    GLib.idle_add(self._toast, "No valid servers in subscription")
            except Exception as e:
                if not silent:
                    GLib.idle_add(self._toast, "Subscription error: {}".format(e))
        threading.Thread(target=worker, daemon=True).start()

    def on_refresh_subs(self, btn):
        if not self.config.get("subscriptions"):
            self._toast("No subscriptions added yet")
            return
        for url in self.config["subscriptions"]:
            self._refresh_sub(url)

    def on_add_link(self, btn):
        dlg = Gtk.Dialog(title="Add Server Link", transient_for=self)
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        entry = Gtk.Entry()
        entry.set_placeholder_text("vless://... / vmess://... / trojan://... / ss://... / socks://... / hy2://...")
        box = dlg.get_content_area()
        box.pack_start(entry, False, False, 0)
        box.set_margin_top(14)
        box.set_margin_bottom(14)
        box.set_margin_start(14)
        box.set_margin_end(14)
        dlg.show_all()
        resp = dlg.run()
        link = entry.get_text().strip()
        dlg.destroy()
        if resp == Gtk.ResponseType.OK and link:
            srv = parse_link(link)
            if srv:
                srv["guid"] = server_guid(srv)
                self.servers.append(srv)
                self.config["servers"] = self.servers
                if not self.config.get("groups"):
                    self.config["groups"] = {"Default": [s["guid"] for s in self.servers]}
                save_config(self.config)
                self._servers_changed()
            else:
                self._toast("Unsupported or invalid link")

    def on_import_file(self, btn):
        dlg = Gtk.FileChooserDialog(
            title="Import configs", transient_for=self,
            action=Gtk.FileChooserAction.OPEN
        )
        dlg.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        resp = dlg.run()
        path = dlg.get_filename()
        dlg.destroy()
        if resp == Gtk.ResponseType.OK and path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
                added = 0
                for line in text.splitlines():
                    srv = parse_link(line)
                    if srv:
                        srv["guid"] = server_guid(srv)
                        if srv["guid"] not in {s["guid"] for s in self.servers}:
                            self.servers.append(srv)
                            added += 1
                self.config["servers"] = self.servers
                if not self.config.get("groups"):
                    self.config["groups"] = {"Default": [s["guid"] for s in self.servers]}
                save_config(self.config)
                self._servers_changed()
                self._toast("Imported {} servers".format(added))
            except Exception as e:
                self._toast("Import failed: {}".format(e))

    def _servers_changed(self):
        self._populate_groups()
        self.circle.queue_draw()

    def on_remove_server(self, widget):
        if self.selected:
            self.servers.remove(self.selected)
            self.selected = None
            self.config["servers"] = self.servers
            save_config(self.config)
            self._servers_changed()

    def _toast(self, msg):
        dlg = Gtk.MessageDialog(
            transient_for=self, flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK, text=msg
        )
        dlg.run()
        dlg.destroy()


class ServerRow(Gtk.ListBoxRow):
    def __init__(self, server, app):
        super().__init__()
        self.server = server
        self.get_style_context().add_class("server-row")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        box.set_margin_start(6)
        box.set_margin_end(6)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        name = Gtk.Label(label=server.get("remark", "Server"), xalign=0)
        name.get_style_context().add_class("server-name")
        name.set_ellipsize(Pango.EllipsizeMode.END)
        top.pack_start(name, True, True, 0)

        ping = server.get("ping")
        if ping is not None:
            pl = Gtk.Label(label="{} ms".format(ping))
            if ping < 150:
                pl.get_style_context().add_class("ping-good")
            elif ping < 400:
                pl.get_style_context().add_class("ping-mid")
            else:
                pl.get_style_context().add_class("ping-bad")
        else:
            pl = Gtk.Label(label="-")
            pl.get_style_context().add_class("ping-none")
        top.pack_start(pl, False, False, 0)
        box.pack_start(top, False, False, 0)

        proto = server["outbound"]["protocol"]
        sub = Gtk.Label(label=proto.upper(), xalign=0)
        sub.get_style_context().add_class("server-sub")
        box.pack_start(sub, False, False, 0)

        s = server["outbound"]["settings"]
        addr = s.get("vnext", [{}])[0].get("address") or \
               s.get("servers", [{}])[0].get("address") or ""
        port = s.get("vnext", [{}])[0].get("port") or \
               s.get("servers", [{}])[0].get("port") or ""
        detail = Gtk.Label(label="{}:{}".format(addr, port), xalign=0)
        detail.get_style_context().add_class("server-detail")
        detail.set_ellipsize(Pango.EllipsizeMode.END)
        box.pack_start(detail, False, False, 0)

        self.add(box)


def main():
    ensure_dirs()
    app = App()
    app.show_all()
    if app.config.get("auto_connect") and app.servers and os.path.exists(XRAY_BIN):
        app.selected = app.servers[0]
        mode = app.config.get("mode", "socks")
        threading.Thread(target=app._connect_worker, args=(app.servers[0], mode), daemon=True).start()
    Gtk.main()


if __name__ == "__main__":
    main()