#!/usr/bin/env bash
# Deploy the relay-tunnel exit server to a remote host.
#
# Usage: bash scripts/deploy.sh kianmhz@146.190.246.7
#        bash scripts/deploy.sh user@host [server_config.json]
#
# Requirements: go, ssh, scp in PATH; user needs sudo on the remote host.
set -euo pipefail

REMOTE="${1:-}"
CONFIG="${2:-server_config.json}"

if [[ -z "$REMOTE" ]]; then
  echo "Usage: $0 user@host [server_config.json]" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config file '$CONFIG' not found." >&2
  echo "Copy server_config.example.json → server_config.json and fill in aes_key_hex." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/relay-server-linux"
SERVICE_TEMPLATE="$ROOT/scripts/relay-tunnel.service"

echo "==> Building Linux amd64 binary..."
cd "$ROOT"
GOOS=linux GOARCH=amd64 go build -o "$BINARY" ./cmd/server
echo "    Built: $BINARY ($(du -sh "$BINARY" | cut -f1))"

# Write a self-contained install script that will run on the droplet.
INSTALL_SCRIPT="$(mktemp /tmp/relay-install-XXXX.sh)"
cat > "$INSTALL_SCRIPT" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
DEPLOY_DIR="$HOME"
sed -i "s|/root|$DEPLOY_DIR|g" ~/relay-tunnel.service
chmod +x "$DEPLOY_DIR/relay-server-linux"
sudo mv ~/relay-tunnel.service /etc/systemd/system/relay-tunnel.service
sudo systemctl daemon-reload
sudo systemctl enable relay-tunnel
sudo systemctl restart relay-tunnel
sleep 1
sudo systemctl status relay-tunnel --no-pager
SCRIPT

echo "==> Copying binary, config, and install script to $REMOTE:~/ ..."
scp "$BINARY" "$CONFIG" "$SERVICE_TEMPLATE" "$INSTALL_SCRIPT" "$REMOTE:~/"
rm "$INSTALL_SCRIPT"

REMOTE_SCRIPT="~/$(basename "$INSTALL_SCRIPT")"

echo "==> Running install on $REMOTE (you may be prompted for your sudo password)..."
# -t allocates a real TTY so sudo can prompt for password interactively
ssh -t "$REMOTE" "bash $REMOTE_SCRIPT; rm $REMOTE_SCRIPT"

echo ""
echo "==> Testing /healthz..."
IP=$(echo "$REMOTE" | sed 's/.*@//')
curl -sf --max-time 5 "http://$IP:8443/healthz" && echo "  OK — server is live at $IP:8443"
