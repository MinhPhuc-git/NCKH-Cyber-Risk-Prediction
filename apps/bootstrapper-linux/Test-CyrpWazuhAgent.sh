#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_AGENT_ID=""
EXPECTED_MANAGER_ADDRESS=""
EXPECTED_MANAGER_PORT=""
EXPECTED_PROTOCOL="tcp"

WAZUH_ROOT="/var/ossec"
CLIENT_KEYS="$WAZUH_ROOT/etc/client.keys"
OSSEC_CONF="$WAZUH_ROOT/etc/ossec.conf"
AGENT_STATE="$WAZUH_ROOT/var/run/wazuh-agentd.state"
AGENT_LOG="$WAZUH_ROOT/logs/ossec.log"

usage() {
    cat <<'USAGE'
Usage:
  sudo bash Test-CyrpWazuhAgent.sh \
    --expected-agent-id 003 \
    --expected-manager-address 192.168.100.247 \
    --expected-manager-port 1514 \
    [--expected-protocol tcp]
USAGE
}

fail() {
    printf '[CYRP] ERROR: %s\n' "$*" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --expected-agent-id)
            EXPECTED_AGENT_ID="$2"
            shift 2
            ;;
        --expected-manager-address)
            EXPECTED_MANAGER_ADDRESS="$2"
            shift 2
            ;;
        --expected-manager-port)
            EXPECTED_MANAGER_PORT="$2"
            shift 2
            ;;
        --expected-protocol)
            EXPECTED_PROTOCOL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

[[ -n "$EXPECTED_AGENT_ID" ]] || fail "--expected-agent-id is required."
[[ -n "$EXPECTED_MANAGER_ADDRESS" ]] || fail "--expected-manager-address is required."
[[ -n "$EXPECTED_MANAGER_PORT" ]] || fail "--expected-manager-port is required."
[[ -f "$CLIENT_KEYS" ]] || fail "client.keys not found."
[[ -f "$OSSEC_CONF" ]] || fail "ossec.conf not found."

read -r AGENT_ID AGENT_NAME AGENT_ADDRESS _ < <(head -n 1 "$CLIENT_KEYS")

mapfile -t MANAGER_VALUES < <(
    python3 - "$OSSEC_CONF" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
client = re.search(r"<client\b[^>]*>.*?</client>", text, flags=re.I | re.S)

if not client:
    raise SystemExit("missing client block")

server = re.search(r"<server\b[^>]*>.*?</server>", client.group(0), flags=re.I | re.S)

if not server:
    raise SystemExit("missing server block")

block = server.group(0)

def get(tag, default=""):
    match = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", block, flags=re.I | re.S)
    return match.group(1).strip() if match else default

print(get("address"))
print(get("port", "1514"))
print(get("protocol", "tcp"))
PY
)

MANAGER_ADDRESS="${MANAGER_VALUES[0]:-}"
MANAGER_PORT="${MANAGER_VALUES[1]:-}"
PROTOCOL="${MANAGER_VALUES[2]:-}"

SERVICE_STATUS="unknown"

if command -v systemctl >/dev/null 2>&1; then
    SERVICE_STATUS="$(systemctl is-active wazuh-agent 2>/dev/null || true)"
fi

CONNECTION_STATUS="unknown"

if [[ -f "$AGENT_STATE" ]]; then
    CONNECTION_STATUS="$(
        awk -F"'" '/^status=/{print $2; exit}' "$AGENT_STATE"
    )"
fi

[[ "$AGENT_ID" == "$EXPECTED_AGENT_ID" ]] || \
    fail "Agent ID mismatch. Expected $EXPECTED_AGENT_ID, got $AGENT_ID."

[[ "$MANAGER_ADDRESS" == "$EXPECTED_MANAGER_ADDRESS" ]] || \
    fail "Manager address mismatch. Expected $EXPECTED_MANAGER_ADDRESS, got $MANAGER_ADDRESS."

[[ "$MANAGER_PORT" == "$EXPECTED_MANAGER_PORT" ]] || \
    fail "Manager port mismatch. Expected $EXPECTED_MANAGER_PORT, got $MANAGER_PORT."

[[ "$PROTOCOL" == "$EXPECTED_PROTOCOL" ]] || \
    fail "Protocol mismatch. Expected $EXPECTED_PROTOCOL, got $PROTOCOL."

[[ "$SERVICE_STATUS" == "active" ]] || \
    fail "wazuh-agent service is not active: $SERVICE_STATUS"

[[ "$CONNECTION_STATUS" == "connected" ]] || {
    if [[ -f "$AGENT_LOG" ]]; then
        tail -n 40 "$AGENT_LOG" >&2 || true
    fi

    fail "Wazuh Agent is not connected: $CONNECTION_STATUS"
}

printf 'ServiceName: wazuh-agent\n'
printf 'ServiceStatus: %s\n' "$SERVICE_STATUS"
printf 'AgentId: %s\n' "$AGENT_ID"
printf 'AgentName: %s\n' "$AGENT_NAME"
printf 'AgentAddress: %s\n' "$AGENT_ADDRESS"
printf 'ManagerAddress: %s\n' "$MANAGER_ADDRESS"
printf 'ManagerPort: %s\n' "$MANAGER_PORT"
printf 'Protocol: %s\n' "$PROTOCOL"
printf 'Connected: true\n'
