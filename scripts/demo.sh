#!/usr/bin/env bash
#
# demo.sh — a guided live demo of the Aegis client/server pipeline.
#
# What it does (end to end):
#   1. Builds the three binaries (aegisd, aegisctl, aegis-agent) in release.
#   2. Starts the server (aegisd): a TLS *ingest* listener for agents plus an
#      operator HTTP API + dashboard. These are on SEPARATE ports by design:
#        - ingest (mutually-pinned TLS, agents connect here):  :8443
#        - operator API / dashboard (loopback by default):     :8080
#   3. Mints a one-time enrollment token via the operator API and prints it with
#      the server's certificate fingerprint (the SHA-256 pin the agent verifies).
#   4. Prints the exact commands to (a) enroll an endpoint and (b) run a
#      monitored shell, including the secure stdin "enroll blob" intake that keeps
#      the token off argv / /proc.
#   5. Prints the operator commands to watch agents and alerts, plus the
#      dashboard URL.
#
# It intentionally does NOT auto-enroll or auto-run a shell: enrollment writes
# per-agent identity to disk and a monitored shell is interactive, so those are
# left as explicit, copy-pasteable steps. The server keeps running until you
# press Ctrl-C; it is then shut down and (optionally) its data dir removed.
#
# ---------------------------------------------------------------------------
# Loopback vs. remote
# ---------------------------------------------------------------------------
# By default everything binds loopback (127.0.0.1) for a single-host demo.
#
# To demo across two hosts, run this on the SERVER host with the server's
# reachable address exported, e.g.:
#
#     LISTEN_ADDR=0.0.0.0:8443 \
#     ADVERTISE_HOST=server.example.com \
#     ./scripts/demo.sh
#
# The agent then enrolls against https://server.example.com:8443 (printed for
# you). Keep the operator API (--http) on loopback — its documented posture is
# loopback-only; reach it via an SSH tunnel rather than exposing :8080.
#
# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
set -euo pipefail

# Where the server's TLS ingest listener binds (agents connect here).
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8443}"
# Where the operator HTTP API + dashboard binds (loopback-only posture).
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:8080}"
# Host:port the AGENT should dial for enrollment/ingest. Defaults to the listen
# address, but for a remote demo set ADVERTISE_HOST to the server's reachable
# name/IP (the agent needs a routable address, not 0.0.0.0).
ADVERTISE_HOST="${ADVERTISE_HOST:-}"
# Operator API base URL aegisctl talks to (always loopback here).
SERVER_API="${SERVER_API:-http://${HTTP_ADDR}}"
# Data directories for this demo (throwaway).
SERVER_DATA="${SERVER_DATA:-./data/demo-server}"
AGENT_DATA="${AGENT_DATA:-./data/demo-agent}"
# Label attached to the enrollment token (defaults to this hostname).
TOKEN_LABEL="${TOKEN_LABEL:-$(hostname)}"
# Set REMOVE_DATA=1 to delete the server data dir on exit.
REMOVE_DATA="${REMOVE_DATA:-0}"

# Resolve the repo root from this script's location so the demo works from
# anywhere, and all relative data dirs are anchored there.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

# The agent's dial target: ADVERTISE_HOST if set, else the listen address with a
# 0.0.0.0 wildcard rewritten to loopback (an agent cannot connect to 0.0.0.0).
if [[ -n "${ADVERTISE_HOST}" ]]; then
    AGENT_SERVER_URL="https://${ADVERTISE_HOST}"
else
    AGENT_SERVER_URL="https://${LISTEN_ADDR/0.0.0.0/127.0.0.1}"
fi

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }

SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        step "Stopping aegisd (pid ${SERVER_PID})"
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    if [[ "${REMOVE_DATA}" == "1" ]]; then
        info "Removing ${SERVER_DATA}"
        rm -rf "${SERVER_DATA}"
        # Remove agent data only if it was created during this run (enrollment is
        # an explicit user step, so we don't remove a pre-existing agent identity).
        if [[ -d "${AGENT_DATA}" ]]; then
            info "Removing ${AGENT_DATA}"
            rm -rf "${AGENT_DATA}"
        fi
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
step "1/5  Building release binaries (aegisd, aegisctl, aegis-agent)"
# ---------------------------------------------------------------------------
cargo build --release -p aegis-server -p aegis-cli -p aegis-agent

BIN="${REPO_ROOT}/target/release"
AEGISD="${BIN}/aegisd"
AEGISCTL="${BIN}/aegisctl"
AEGIS_AGENT="${BIN}/aegis-agent"
for b in "${AEGISD}" "${AEGISCTL}" "${AEGIS_AGENT}"; do
    [[ -x "$b" ]] || { echo "missing built binary: $b" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
step "2/5  Starting the server"
# ---------------------------------------------------------------------------
info "ingest (TLS, agents):      ${LISTEN_ADDR}"
info "operator API + dashboard:  ${HTTP_ADDR}"
info "data dir:                  ${SERVER_DATA}"
mkdir -p "${SERVER_DATA}"
"${AEGISD}" run \
    --listen "${LISTEN_ADDR}" \
    --http "${HTTP_ADDR}" \
    --data-dir "${SERVER_DATA}" \
    >"${SERVER_DATA}/aegisd.log" 2>&1 &
SERVER_PID=$!
info "aegisd pid ${SERVER_PID} (logs: ${SERVER_DATA}/aegisd.log)"

# Wait for the operator API to answer (it exposes the cert fingerprint + proto
# version once it is listening). Poll, don't sleep-and-hope.
info "waiting for the operator API at ${SERVER_API} ..."
for _ in $(seq 1 50); do
    if "${AEGISCTL}" status --server "${SERVER_API}" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
        echo "aegisd exited early; see ${SERVER_DATA}/aegisd.log" >&2
        exit 1
    fi
    sleep 0.2
done
"${AEGISCTL}" status --server "${SERVER_API}" >/dev/null 2>&1 \
    || { echo "operator API did not come up in time" >&2; exit 1; }

bold "Server is up. Identity:"
"${AEGISCTL}" status --server "${SERVER_API}"

# ---------------------------------------------------------------------------
step "3/5  Minting a one-time enrollment token"
# ---------------------------------------------------------------------------
# Use --json so we can extract the token and fingerprint for scripting. The
# tiny in-tree JSON extraction below avoids a hard `jq` dependency.
TOKEN_JSON="$("${AEGISCTL}" enroll-token create --label "${TOKEN_LABEL}" --server "${SERVER_API}" --json)"

extract_json_str() {
    # extract_json_str <key> <<< "$json" — minimal string-field reader.
    local key="$1"
    sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -n1
}
TOKEN="$(printf '%s' "${TOKEN_JSON}" | extract_json_str token)"
FINGERPRINT="$(printf '%s' "${TOKEN_JSON}" | extract_json_str fingerprint)"

if [[ -z "${TOKEN}" || -z "${FINGERPRINT}" ]]; then
    echo "could not parse token/fingerprint from: ${TOKEN_JSON}" >&2
    exit 1
fi
info "token:       ${TOKEN}"
info "fingerprint: ${FINGERPRINT}"
info "(the fingerprint is the SHA-256 pin the agent verifies on the TLS leaf)"

# ---------------------------------------------------------------------------
step "4/5  Enroll an endpoint, then run a monitored shell"
# ---------------------------------------------------------------------------
bold "Option A — simple (token + pin on argv; fine for a local demo):"
cat <<EOF
    ${AEGIS_AGENT} enroll \\
        --server ${AGENT_SERVER_URL} \\
        --token ${TOKEN} \\
        --pin ${FINGERPRINT} \\
        --data-dir ${AGENT_DATA}
EOF

bold "Option B — secure intake (keeps the token off argv / /proc):"
# Build the AEGIS-ENROLL blob = base64( token_bytes || pin_32_raw_bytes ).
# The token is its literal UTF-8 bytes; the pin is the fingerprint hex decoded
# to 32 raw bytes. We assemble it here so the demo can show the exact value to
# pipe over stdin (`--enroll-blob -`). This mirrors parse_enroll_blob().
if command -v xxd >/dev/null 2>&1; then
    PIN_BYTES_CMD='xxd -r -p'
elif command -v perl >/dev/null 2>&1; then
    PIN_BYTES_CMD='perl -ne "s/([0-9a-f]{2})/print chr hex \$1/gie"'
else
    PIN_BYTES_CMD=''
fi
if [[ -n "${PIN_BYTES_CMD}" ]]; then
    ENROLL_BLOB="AEGIS-ENROLL $(
        { printf '%s' "${TOKEN}"; printf '%s' "${FINGERPRINT}" | eval "${PIN_BYTES_CMD}"; } \
            | base64 | tr -d '\n'
    )"
    cat <<EOF
    printf '%s' '${ENROLL_BLOB}' | ${AEGIS_AGENT} enroll \\
        --server ${AGENT_SERVER_URL} \\
        --enroll-blob - \\
        --data-dir ${AGENT_DATA}
EOF
else
    info "(install xxd or perl to have this script print a ready-made enroll blob)"
    info "blob format: AEGIS-ENROLL <base64( token_bytes || pin_32_raw_bytes )>"
fi

bold "Then run a monitored interactive shell (content-free behavioral telemetry):"
cat <<EOF
    # Local-only behavioral demo (prints timing/structure telemetry to stderr;
    # no network, no enrollment needed):
    ${AEGIS_AGENT} shell --print-events

    # Full agent (forwards telemetry to the server using the enrolled identity):
    ${AEGIS_AGENT} run \\
        --server ${AGENT_SERVER_URL} \\
        --data-dir ${AGENT_DATA}
EOF
info "Tip: inside the shell, paste a long command and type some others quickly —"
info "metronomic timing and whole-line pastes are what tip the detector to Agent."

# ---------------------------------------------------------------------------
step "5/5  Observe (run these in another terminal while the agent is active)"
# ---------------------------------------------------------------------------
cat <<EOF
    ${AEGISCTL} agents  --server ${SERVER_API}
    ${AEGISCTL} alerts  --server ${SERVER_API}
    ${AEGISCTL} status  --server ${SERVER_API}
EOF
info "Dashboard: http://${HTTP_ADDR}/"
if [[ "${HTTP_ADDR}" != 127.0.0.1:* && "${HTTP_ADDR}" != localhost:* ]]; then
    info "(operator API is bound non-loopback; prefer an SSH tunnel to reach it)"
fi

bold ""
bold "Server is running. Press Ctrl-C to stop it."
# Wait on the server process so Ctrl-C triggers cleanup via the trap.
wait "${SERVER_PID}"
