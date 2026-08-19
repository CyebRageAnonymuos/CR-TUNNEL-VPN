#!/usr/bin/env python3

import base64
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import urllib.parse
import urllib.request

try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gtk, Gdk, GLib
except Exception:
    print("GTK3 is required. Install it with: sudo apt install python3-gi gir1.2-gtk-3.0")
    sys.exit(1)

APP_NAME = "CR Tunnel"
CONFIG_DIR = os.path.expanduser("~/.config/crtunnel")
DATA_DIR = os.path.expanduser("~/.local/share/crtunnel")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
XRAY_BIN = os.path.join(DATA_DIR, "xray")
XRAY_PORT = 10808
SOCKS_PORT = 10808
HTTP_PORT = 10809
TUN = "tun"

XRAY_RELEASE_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-{}.zip"

DEFAULT_CONFIG = {
    "subscriptions": [],
    "servers": [],
    "auto_connect": False,
    "mode": "socks",
    "dns": "1.1.1.1"
}

ACCENT = "#00E5FF"
ACCENT_PURPLE = "#A855F7"


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
        import zipfile
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
    if "@" in info:
        uuid, addr = info.split("@", 1)
    else:
        uuid, addr = "", info
    host = addr
    port = 443
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        if p.isdigit():
            port = int(p)
    q = urllib.parse.parse_qs(uri.query)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    stream = {}
    net = params.get("type", "tcp")
    stream["network"] = net
    if net in ("ws", "http"):
        stream["security"] = params.get("security", "none")
        ws = {}
        if params.get("path"):
            ws["path"] = params["path"]
        if params.get("host"):
            ws["headers"] = {"Host": params["host"]}
        stream[net + "Settings"] = ws
    else:
        stream["security"] = params.get("security", "none")
    if params.get("sni"):
        stream["sni"] = params["sni"]
    if params.get("fp"):
        stream["fingerprint"] = params["fp"]
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
    return {"remark": remark, "outbound": outbound}


def parse_trojan(uri, remark):
    info = uri.netloc
    if "@" in info:
        password, addr = info.split("@", 1)
    else:
        password, addr = "", info
    host = addr
    port = 443
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        if p.isdigit():
            port = int(p)
    q = urllib.parse.parse_qs(uri.query)
    params = {k: (v[0] if v else "") for k, v in q.items()}
    stream = {"network": "tcp", "security": "tls"}
    if params.get("sni"):
        stream["sni"] = params["sni"]
    if params.get("type", "tcp") in ("ws", "http"):
        net = params["type"]
        stream["network"] = net
        ws = {}
        if params.get("path"):
            ws["path"] = params["path"]
        if params.get("host"):
            ws["headers"] = {"Host": params["host"]}
        stream[net + "Settings"] = ws
    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": password,
                "level": 0
            }]
        },
        "streamSettings": stream
    }
    return {"remark": remark, "outbound": outbound}


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
    if data.get("net") == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", ""),
            "headers": {"Host": data.get("host", "")}
        }
    elif data.get("net") == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", ""), "multiMode": False}
    elif data.get("net") == "http":
        stream["httpSettings"] = {"path": data.get("path", ""), "host": [data.get("host", "")]}
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
    return {"remark": remark, "outbound": outbound}


def parse_ss(uri, remark):
    info = uri.netloc
    host = ""
    port = 443
    method = ""
    password = ""
    if "@" in info:
        head, addr = info.split("@", 1)
        host = addr
        if ":" in addr:
            host, p = addr.rsplit(":", 1)
            if p.isdigit():
                port = int(p)
        try:
            dec = decode_b64_pad(head)
            if ":" in dec:
                method, password = dec.split(":", 1)
        except Exception:
            pass
    else:
        dec = decode_b64_pad(info)
        if ":" in dec:
            method, password = dec.split(":", 1)
    if not method or not password:
        return None
    stream = {"network": "tcp", "security": "none"}
    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password
            }]
        },
        "streamSettings": stream
    }
    return {"remark": remark, "outbound": outbound}


def parse_link(raw_link):
    link = raw_link.strip()
    if not link:
        return None
    if link.startswith("vmess://"):
        return parse_vmess(urllib.parse.urlparse(link), "vmess")
    if link.startswith("vless://"):
        return parse_vless(urllib.parse.urlparse(link), "vless")
    if link.startswith("trojan://"):
        return parse_trojan(urllib.parse.urlparse(link), "trojan")
    if link.startswith("ss://"):
        return parse_ss(urllib.parse.urlparse(link), "ss")
    return None


def fetch_subscription(url):
    req = urllib.request.Request(url, headers={"User-Agent": "crtunnel"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content = resp.read()
    text = content.decode("utf-8", errors="replace")
    if text.startswith("{"):
        data = json.loads(text)
        text = data.get("data", "")
    if text.startswith("vless://") or text.startswith("vmess://") or text.startswith("ss://") or text.startswith("trojan://"):
        return text.splitlines()
    if any(c in text for c in "-_"):
        try:
            decoded = decode_b64_pad(text.replace("\n", ""))
            if decoded:
                lines = [l.strip() for l in decoded.splitlines() if l.strip()]
                if any(l.startswith(("vless://", "vmess://", "ss://", "trojan://")) for l in lines):
                    return lines
        except Exception:
            pass
    return text.splitlines()


class TunnelManager:
    def __init__(self):
        self.process = None
        self.config_path = os.path.join(CONFIG_DIR, "xray-config.json")
        self.status = "stopped"

    def build_config(self, server, mode):
        inbound = {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }
        http_in = {
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": HTTP_PORT,
            "protocol": "http",
            "settings": {"allowTransparent": False}
        }
        inbounds = [inbound, http_in]
        if mode == TUN:
            tun_in = {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "address": ["10.0.0.1"],
                    "mtu": 1500,
                    "autoRoute": True,
                    "strictRoute": False
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }
            inbounds.insert(0, tun_in)
        outbound = json.loads(json.dumps(server["outbound"]))
        outbound["tag"] = "proxy"
        cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "dns": {
                "servers": [{"address": DEFAULT_CONFIG["dns"], "queryStrategy": "UseIP"}]
            }
        }
        return cfg

    def start(self, server, mode):
        self.stop()
        cfg = self.build_config(server, mode)
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


class App(Gtk.Window):
    def __init__(self):
        super().__init__(title=APP_NAME)
        self.set_default_size(460, 620)
        self.config = load_config()
        self.tunnel = TunnelManager()
        self.servers = self.config.get("servers", [])
        self.selected = None
        self.builder = self._build_ui()
        self._apply_style()
        self.refresh_server_list()
        self.connect("destroy", self.on_close)
        self.connect("delete-event", self.on_delete)
        signal.signal(signal.SIGINT, self._sigint)

    def _sigint(self, *args):
        self.tunnel.stop()
        Gtk.main_quit()

    def on_delete(self, widget, event):
        self.tunnel.stop()
        return False

    def on_close(self, widget):
        self.tunnel.stop()

    def _build_ui(self):
        builder = Gtk.Builder()
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        vbox.set_margin_top(12)
        vbox.set_margin_bottom(12)
        vbox.set_margin_start(12)
        vbox.set_margin_end(12)
        self.add(vbox)

        title = Gtk.Label(label=APP_NAME)
        title.get_style_context().add_class("title")
        vbox.pack_start(title, False, False, 0)

        self.status_label = Gtk.Label(label="Disconnected")
        self.status_label.get_style_context().add_class("status-off")
        vbox.pack_start(self.status_label, False, False, 0)

        self.remark_label = Gtk.Label(label="No server selected")
        vbox.pack_start(self.remark_label, False, False, 0)

        connect_btn = Gtk.Button(label="Connect")
        connect_btn.get_style_context().add_class("connect")
        connect_btn.connect("clicked", self.on_connect)
        vbox.pack_start(connect_btn, False, False, 0)
        self.connect_btn = connect_btn

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        add_sub = Gtk.Button(label="Add Subscription")
        add_sub.connect("clicked", self.on_add_subscription)
        add_link = Gtk.Button(label="Add Link")
        add_link.connect("clicked", self.on_add_link)
        bar.pack_start(add_sub, True, True, 0)
        bar.pack_start(add_link, True, True, 0)
        vbox.pack_start(bar, False, False, 0)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.liststore = Gtk.ListStore(str, str, object)
        self.treeview = Gtk.TreeView(model=self.liststore)
        col = Gtk.TreeViewColumn("Server", Gtk.CellRendererText(), text=0)
        self.treeview.append_column(col)
        col2 = Gtk.TreeViewColumn("Status", Gtk.CellRendererText(), text=1)
        self.treeview.append_column(col2)
        self.treeview.connect("row-activated", self.on_row_activated)
        scroller.add(self.treeview)
        vbox.pack_start(scroller, True, True, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        remove_btn = Gtk.Button(label="Remove")
        remove_btn.connect("clicked", self.on_remove_server)
        refresh_btn = Gtk.Button(label="Refresh Subs")
        refresh_btn.connect("clicked", self.on_refresh_subs)
        actions.pack_start(remove_btn, True, True, 0)
        actions.pack_start(refresh_btn, True, True, 0)
        vbox.pack_start(actions, False, False, 0)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        mode_row.pack_start(Gtk.Label(label="Mode:"), False, False, 0)
        self.mode_combo = Gtk.ComboBoxText()
        self.mode_combo.append("socks", "Proxy (SOCKS/HTTP)")
        self.mode_combo.append(TUN, "TUN (System-wide)")
        self.mode_combo.set_active(0)
        mode_row.pack_start(self.mode_combo, True, True, 0)
        vbox.pack_start(mode_row, False, False, 0)

        hint = Gtk.Label(label="SOCKS: 127.0.0.1:{}  HTTP: 127.0.0.1:{}".format(SOCKS_PORT, HTTP_PORT))
        hint.get_style_context().add_class("hint")
        vbox.pack_start(hint, False, False, 0)

        for i in range(len(self.config.get("subscriptions", []))):
            self._refresh_sub(self.config["subscriptions"][i], silent=True)

        return builder

    def _apply_style(self):
        css = b"""
        .title { font-size: 24px; font-weight: bold; color: #00E5FF; }
        .status-off { color: #ff5252; font-weight: bold; }
        .status-on { color: #00E676; font-weight: bold; }
        .connect { background-color: #00E5FF; color: #05070F; font-weight: bold; }
        .hint { color: #888888; font-size: 11px; }
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css)
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen,
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def refresh_server_list(self):
        self.liststore.clear()
        for s in self.servers:
            remark = s.get("remark", "")
            self.liststore.append([remark, "", s])
        if self.servers and self.selected is None:
            self.selected = self.servers[0]
            self.remark_label.set_text(self.selected.get("remark", ""))

    def on_row_activated(self, tree, path, col):
        it = self.liststore.get_iter(path)
        self.selected = self.liststore.get_value(it, 2)
        self.remark_label.set_text(self.selected.get("remark", ""))

    def on_connect(self, btn):
        if self.tunnel.status == "running":
            self.tunnel.stop()
            self.status_label.set_text("Disconnected")
            self.status_label.get_style_context().remove_class("status-on")
            self.status_label.get_style_context().add_class("status-off")
            self.connect_btn.set_label("Connect")
            return
        if not self.selected:
            self._toast("Select a server first")
            return
        if not os.path.exists(XRAY_BIN):
            self._toast("Xray-core not found. Use install.sh first.")
            return
        mode = self.mode_combo.get_active_id() or "socks"
        if mode == TUN:
            if os.geteuid() != 0:
                self._toast("TUN mode needs root: sudo crtunnel.py")
                return
        threading.Thread(target=self._connect_worker, args=(self.selected, mode), daemon=True).start()

    def _connect_worker(self, server, mode):
        try:
            self.tunnel.start(server, mode)
        except Exception as e:
            GLib.idle_add(self._toast, "Failed: {}".format(e))
            return
        GLib.idle_add(self._connected)

    def _connected(self):
        self.status_label.set_text("Connected")
        self.status_label.get_style_context().remove_class("status-off")
        self.status_label.get_style_context().add_class("status-on")
        self.connect_btn.set_label("Disconnect")

    def on_add_subscription(self, btn):
        dialog = Gtk.Dialog(title="Add Subscription", transient_for=self)
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        entry = Gtk.Entry()
        entry.set_placeholder_text("https://example.com/sub")
        box = dialog.get_content_area()
        box.pack_start(entry, False, False, 0)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        dialog.show_all()
        response = dialog.run()
        url = entry.get_text().strip()
        dialog.destroy()
        if response == Gtk.ResponseType.OK and url:
            self.config.setdefault("subscriptions", []).append(url)
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
                        parsed.append(srv)
                if parsed:
                    existing = set()
                    for s in self.servers:
                        existing.add(json.dumps(s["outbound"], sort_keys=True))
                    added = 0
                    for srv in parsed:
                        key = json.dumps(srv["outbound"], sort_keys=True)
                        if key not in existing:
                            self.servers.append(srv)
                            existing.add(key)
                            added += 1
                    self.config["servers"] = self.servers
                    save_config(self.config)
                    GLib.idle_add(self.refresh_server_list)
                    if not silent:
                        GLib.idle_add(self._toast, "Added {} servers".format(added))
                elif not silent:
                    GLib.idle_add(self._toast, "No valid servers in subscription")
            except Exception as e:
                if not silent:
                    GLib.idle_add(self._toast, "Subscription error: {}".format(e))
        threading.Thread(target=worker, daemon=True).start()

    def on_refresh_subs(self, btn):
        for url in self.config.get("subscriptions", []):
            self._refresh_sub(url)

    def on_add_link(self, btn):
        dialog = Gtk.Dialog(title="Add Server Link", transient_for=self)
        dialog.add_buttons(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK)
        entry = Gtk.Entry()
        entry.set_placeholder_text("vless://... or vmess://... or trojan://... or ss://...")
        box = dialog.get_content_area()
        box.pack_start(entry, False, False, 0)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)
        dialog.show_all()
        response = dialog.run()
        link = entry.get_text().strip()
        dialog.destroy()
        if response == Gtk.ResponseType.OK and link:
            srv = parse_link(link)
            if srv:
                self.servers.append(srv)
                self.config["servers"] = self.servers
                save_config(self.config)
                self.refresh_server_list()
            else:
                self._toast("Unsupported or invalid link")

    def on_remove_server(self, btn):
        sel = self.treeview.get_selection()
        model, paths = sel.get_selected_rows()
        if not paths:
            return
        path = paths[0]
        it = model.get_iter(path)
        server = model.get_value(it, 2)
        if server in self.servers:
            self.servers.remove(server)
        self.config["servers"] = self.servers
        save_config(self.config)
        self.refresh_server_list()

    def _toast(self, msg):
        dlg = Gtk.MessageDialog(
            transient_for=self,
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=msg
        )
        dlg.run()
        dlg.destroy()


def main():
    ensure_dirs()
    app = App()
    app.show_all()
    Gtk.main()


if __name__ == "__main__":
    main()