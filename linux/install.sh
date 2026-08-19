#!/bin/bash
set -e

APP_DIR="$HOME/.local/share/crtunnel"
BIN_DIR="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XRAY_BIN="$APP_DIR/xray"

echo ""
echo "  CR TUNNEL - Linux Installer"
echo "  ==========================="
echo ""

check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: '$1' is required but not installed."
    echo "       Install it with: $2"
    exit 1
  fi
}

check_cmd python3 "sudo apt install python3"
check_cmd unzip "sudo apt install unzip"
check_cmd curl "sudo apt install curl"

python3 - <<'EOF'
import sys
try:
    import gi
    gi.require_version("Gtk", "3.0")
except Exception:
    print("ERROR: GTK3 Python bindings are required.")
    print("       Install them with: sudo apt install python3-gi gir1.2-gtk-3.0")
    sys.exit(1)
EOF

echo "[1/3] Creating directories..."
mkdir -p "$APP_DIR" "$BIN_DIR"

echo "[2/3] Installing CR Tunnel launcher..."
cp "$SCRIPT_DIR/crtunnel.py" "$APP_DIR/crtunnel.py"
chmod +x "$APP_DIR/crtunnel.py"
cat > "$BIN_DIR/crtunnel" <<EOF
#!/bin/bash
exec python3 "$APP_DIR/crtunnel.py" "\$@"
EOF
chmod +x "$BIN_DIR/crtunnel"
if [ -w /usr/local/bin ] || command -v sudo >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null; then
    sudo ln -sf "$BIN_DIR/crtunnel" /usr/local/bin/crtunnel
    echo "  -> Also linked to /usr/local/bin (works with 'sudo crtunnel')"
  fi
fi

echo "[3/3] Downloading Xray-core..."
ARCH=""
case "$(uname -m)" in
  x86_64|amd64) ARCH="64" ;;
  aarch64|arm64) ARCH="arm64-v8a" ;;
  armv7l|armv6l) ARCH="arm32-v7a" ;;
  *) echo "ERROR: Unsupported architecture: $(uname -m)"; exit 1 ;;
esac

URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$ARCH.zip"
ZIP="$APP_DIR/xray.zip"
curl -L --progress-bar -o "$ZIP" "$URL"
unzip -o -j "$ZIP" xray -d "$APP_DIR"
rm -f "$ZIP"
chmod +x "$XRAY_BIN"

echo ""
echo "  Installation complete!"
echo ""
echo "  Run: crtunnel"
echo ""
echo "  Note: if '$HOME/.local/bin' is not in your PATH, add it:"
echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "        (add the line above to ~/.bashrc or ~/.zshrc)"
echo ""
echo "  TUN (system-wide) mode requires root: sudo crtunnel"
echo "  (if 'sudo crtunnel' fails, use: sudo \$(which crtunnel))"
echo ""