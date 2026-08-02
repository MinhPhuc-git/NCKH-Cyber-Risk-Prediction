#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ENROLLMENT_FILE=""
FORCE_REENROLL=0
KEEP_ENROLLMENT_FILE=0
EXPECTED_OLD_AGENT_ID=""
CONNECTION_TIMEOUT_SECONDS=180

WAZUH_ROOT="/var/ossec"
MANAGE_AGENTS="$WAZUH_ROOT/bin/manage_agents"
AGENTD_TEST="$WAZUH_ROOT/bin/wazuh-agentd"
OSSEC_CONF="$WAZUH_ROOT/etc/ossec.conf"
CLIENT_KEYS="$WAZUH_ROOT/etc/client.keys"
AGENT_STATE="$WAZUH_ROOT/var/run/wazuh-agentd.state"
AGENT_LOG="$WAZUH_ROOT/logs/ossec.log"
CYRP_STATE_DIR="/var/lib/cyrp"
CYRP_SECRET_DIR="$CYRP_STATE_DIR/secrets"
CYRP_STATE_FILE="$CYRP_STATE_DIR/bootstrapper-state.json"
CYRP_AGENT_TOKEN_FILE="$CYRP_SECRET_DIR/agent-token"

BACKUP_DIR=""
MIGRATION_STARTED=0
MIGRATION_COMPLETED=0
SERVICE_WAS_ACTIVE=0

usage() {
    cat <<'USAGE'
Usage:
  sudo bash Install-CyrpWazuhFromEnrollmentFile.sh \
    --enrollment-file <path> \
    --force-reenroll \
    --expected-old-agent-id 002 \
    [--connection-timeout-seconds 180] \
    [--keep-enrollment-file]

This phase intentionally replaces the current Wazuh Agent identity on an
already-installed Linux endpoint. Without --force-reenroll, an existing
different Agent ID is never overwritten.
USAGE
}

log() {
    printf '[CYRP] %s\n' "$*"
}

fail() {
    printf '[CYRP] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

json_get() {
    local field="$1"

    python3 - "$ENROLLMENT_FILE" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1], sys.argv[2]

with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

value = payload.get(field)

if value is None:
    raise SystemExit(f"missing field: {field}")

if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
else:
    print(str(value))
PY
}

read_existing_identity() {
    EXISTING_AGENT_ID=""
    EXISTING_AGENT_NAME=""
    EXISTING_AGENT_ADDRESS=""

    if [[ -s "$CLIENT_KEYS" ]]; then
        local first_line
        first_line="$(head -n 1 "$CLIENT_KEYS" || true)"

        if [[ -n "$first_line" ]]; then
            read -r EXISTING_AGENT_ID EXISTING_AGENT_NAME EXISTING_AGENT_ADDRESS _ <<<"$first_line"
        fi
    fi
}

set_manager_configuration() {
    local manager_address="$1"
    local manager_port="$2"
    local protocol="$3"

    python3 - "$OSSEC_CONF" "$manager_address" "$manager_port" "$protocol" <<'PY'
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

path = Path(sys.argv[1])
address = escape(sys.argv[2])
port = escape(sys.argv[3])
protocol = escape(sys.argv[4])

text = path.read_text(encoding="utf-8")
client_match = re.search(r"<client\b[^>]*>.*?</client>", text, flags=re.I | re.S)

if not client_match:
    raise SystemExit("No <client> block was found in ossec.conf")

client_block = client_match.group(0)
server_match = re.search(r"<server\b[^>]*>.*?</server>", client_block, flags=re.I | re.S)

if not server_match:
    raise SystemExit("No <server> block was found inside <client>")

server_block = server_match.group(0)

def set_tag(block: str, tag: str, value: str) -> str:
    pattern = rf"<{tag}\b[^>]*>.*?</{tag}>"
    replacement = f"<{tag}>{value}</{tag}>"

    if re.search(pattern, block, flags=re.I | re.S):
        return re.sub(pattern, replacement, block, count=1, flags=re.I | re.S)

    return re.sub(
        r"</server>",
        f"  {replacement}\n</server>",
        block,
        count=1,
        flags=re.I,
    )

server_block = set_tag(server_block, "address", address)
server_block = set_tag(server_block, "port", port)
server_block = set_tag(server_block, "protocol", protocol)

new_client_block = (
    client_block[: server_match.start()]
    + server_block
    + client_block[server_match.end() :]
)

new_text = (
    text[: client_match.start()]
    + new_client_block
    + text[client_match.end() :]
)

path.write_text(new_text, encoding="utf-8")
PY
}

on_exit() {
    local exit_code=$?
    trap - EXIT

    if [[ "$exit_code" -ne 0 && "$MIGRATION_STARTED" -eq 1 && "$MIGRATION_COMPLETED" -eq 0 && -n "$BACKUP_DIR" ]]; then
        printf '[CYRP] Migration failed. Restoring Wazuh Agent files from %s\n' "$BACKUP_DIR" >&2

        if [[ -f "$BACKUP_DIR/ossec.conf" ]]; then
            cp -a "$BACKUP_DIR/ossec.conf" "$OSSEC_CONF"
        fi

        if [[ -f "$BACKUP_DIR/client.keys" ]]; then
            cp -a "$BACKUP_DIR/client.keys" "$CLIENT_KEYS"
        fi

        if [[ -f "$BACKUP_DIR/bootstrapper-state.json" ]]; then
            install -d -m 700 "$CYRP_STATE_DIR"
            cp -a "$BACKUP_DIR/bootstrapper-state.json" "$CYRP_STATE_FILE"
        else
            rm -f "$CYRP_STATE_FILE"
        fi

        if [[ -f "$BACKUP_DIR/agent-token" ]]; then
            install -d -m 700 "$CYRP_SECRET_DIR"
            cp -a "$BACKUP_DIR/agent-token" "$CYRP_AGENT_TOKEN_FILE"
        else
            rm -f "$CYRP_AGENT_TOKEN_FILE"
        fi

        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart wazuh-agent >/dev/null 2>&1 || true
        elif [[ -x "$WAZUH_ROOT/bin/wazuh-control" ]]; then
            "$WAZUH_ROOT/bin/wazuh-control" restart >/dev/null 2>&1 || true
        fi
    fi

    exit "$exit_code"
}

trap on_exit EXIT

while [[ $# -gt 0 ]]; do
    case "$1" in
        --enrollment-file)
            [[ $# -ge 2 ]] || fail "--enrollment-file requires a value"
            ENROLLMENT_FILE="$2"
            shift 2
            ;;
        --force-reenroll)
            FORCE_REENROLL=1
            shift
            ;;
        --expected-old-agent-id)
            [[ $# -ge 2 ]] || fail "--expected-old-agent-id requires a value"
            EXPECTED_OLD_AGENT_ID="$2"
            shift 2
            ;;
        --connection-timeout-seconds)
            [[ $# -ge 2 ]] || fail "--connection-timeout-seconds requires a value"
            CONNECTION_TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --keep-enrollment-file)
            KEEP_ENROLLMENT_FILE=1
            shift
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

[[ "$(id -u)" -eq 0 ]] || fail "Run this script with sudo."
[[ -n "$ENROLLMENT_FILE" ]] || fail "--enrollment-file is required."
[[ -f "$ENROLLMENT_FILE" ]] || fail "Enrollment file not found: $ENROLLMENT_FILE"
[[ "$CONNECTION_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || fail "Connection timeout must be an integer."
(( CONNECTION_TIMEOUT_SECONDS >= 30 && CONNECTION_TIMEOUT_SECONDS <= 900 )) || \
    fail "Connection timeout must be between 30 and 900 seconds."

require_command python3
require_command awk
require_command grep
require_command cp
require_command chmod
require_command chown
require_command stat
require_command install
require_command timeout
require_command head
require_command tail

[[ -x "$MANAGE_AGENTS" ]] || fail "Wazuh manage_agents was not found at $MANAGE_AGENTS"
[[ -f "$OSSEC_CONF" ]] || fail "Wazuh ossec.conf was not found at $OSSEC_CONF"
[[ -f "$CLIENT_KEYS" ]] || fail "Wazuh client.keys was not found at $CLIENT_KEYS"

chmod 600 "$ENROLLMENT_FILE"

DEVICE_ID="$(json_get deviceId)"
INSTALLATION_ID="$(json_get installationId)"
TARGET_AGENT_ID="$(json_get agentId)"
TARGET_AGENT_NAME="$(json_get agentName)"
MANAGER_ADDRESS="$(json_get managerAddress)"
MANAGER_PORT="$(json_get managerPort)"
PROTOCOL="$(json_get protocol)"
AGENT_TOKEN="$(json_get agentToken)"
CLIENT_KEY="$(json_get clientKey)"

[[ "$TARGET_AGENT_ID" =~ ^[0-9]{3,}$ ]] || fail "Invalid target Agent ID: $TARGET_AGENT_ID"
[[ -n "$TARGET_AGENT_NAME" ]] || fail "Target Agent name is empty."
[[ -n "$MANAGER_ADDRESS" ]] || fail "Manager address is empty."
[[ "$MANAGER_PORT" =~ ^[0-9]+$ ]] || fail "Manager port is invalid."
(( MANAGER_PORT >= 1 && MANAGER_PORT <= 65535 )) || fail "Manager port is outside the valid range."
[[ "$PROTOCOL" == "tcp" || "$PROTOCOL" == "udp" ]] || fail "Protocol must be tcp or udp."
[[ -n "$AGENT_TOKEN" ]] || fail "CYRP agent token is empty."
[[ -n "$CLIENT_KEY" ]] || fail "Wazuh client key is empty."

read_existing_identity

if [[ -n "$EXISTING_AGENT_ID" && "$EXISTING_AGENT_ID" != "$TARGET_AGENT_ID" ]]; then
    [[ "$FORCE_REENROLL" -eq 1 ]] || fail \
        "Endpoint already uses Agent $EXISTING_AGENT_ID. Re-run with --force-reenroll only when replacement is intentional."

    if [[ -n "$EXPECTED_OLD_AGENT_ID" && "$EXISTING_AGENT_ID" != "$EXPECTED_OLD_AGENT_ID" ]]; then
        fail "Expected old Agent $EXPECTED_OLD_AGENT_ID, but endpoint currently uses Agent $EXISTING_AGENT_ID."
    fi
fi

if [[ -n "$EXPECTED_OLD_AGENT_ID" && -z "$EXISTING_AGENT_ID" ]]; then
    fail "Expected old Agent $EXPECTED_OLD_AGENT_ID, but client.keys has no current identity."
fi

log "Current identity: ${EXISTING_AGENT_ID:-none} ${EXISTING_AGENT_NAME:-}"
log "Target identity: $TARGET_AGENT_ID $TARGET_AGENT_NAME"
log "Manager: $MANAGER_ADDRESS:$MANAGER_PORT/$PROTOCOL"

if [[ "$PROTOCOL" == "tcp" ]]; then
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 5 "$MANAGER_ADDRESS" "$MANAGER_PORT" || \
            fail "Cannot reach Wazuh Manager at $MANAGER_ADDRESS:$MANAGER_PORT/tcp"
    else
        timeout 5 bash -c "</dev/tcp/$MANAGER_ADDRESS/$MANAGER_PORT" || \
            fail "Cannot reach Wazuh Manager at $MANAGER_ADDRESS:$MANAGER_PORT/tcp"
    fi
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wazuh-agent; then
    SERVICE_WAS_ACTIVE=1
fi

BACKUP_DIR="/var/backups/cyrp/wazuh-reenroll-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$BACKUP_DIR"
cp -a "$OSSEC_CONF" "$BACKUP_DIR/ossec.conf"
cp -a "$CLIENT_KEYS" "$BACKUP_DIR/client.keys"

if [[ -f "$CYRP_STATE_FILE" ]]; then
    cp -a "$CYRP_STATE_FILE" "$BACKUP_DIR/bootstrapper-state.json"
fi

if [[ -f "$CYRP_AGENT_TOKEN_FILE" ]]; then
    cp -a "$CYRP_AGENT_TOKEN_FILE" "$BACKUP_DIR/agent-token"
fi

MIGRATION_STARTED=1

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop wazuh-agent
elif [[ -x "$WAZUH_ROOT/bin/wazuh-control" ]]; then
    "$WAZUH_ROOT/bin/wazuh-control" stop
else
    fail "Unable to stop the Wazuh Agent service."
fi

client_owner="$(stat -c '%u' "$CLIENT_KEYS")"
client_group="$(stat -c '%g' "$CLIENT_KEYS")"
client_mode="$(stat -c '%a' "$CLIENT_KEYS")"

if [[ "$EXISTING_AGENT_ID" != "$TARGET_AGENT_ID" ]]; then
    : > "$CLIENT_KEYS"
    chown "$client_owner:$client_group" "$CLIENT_KEYS"
    chmod "$client_mode" "$CLIENT_KEYS"

    if ! import_output="$(
        printf 'y\n' |
            "$MANAGE_AGENTS" -i "$CLIENT_KEY" 2>&1
    )"; then
        printf '%s\n' "$import_output" >&2
        fail "manage_agents failed while importing Agent $TARGET_AGENT_ID."
    fi

    chown "$client_owner:$client_group" "$CLIENT_KEYS"
    chmod "$client_mode" "$CLIENT_KEYS"
else
    log "Target Agent identity is already present; client key import was skipped."
fi

read_existing_identity

[[ "$EXISTING_AGENT_ID" == "$TARGET_AGENT_ID" ]] || \
    fail "Imported client.keys ID is $EXISTING_AGENT_ID instead of $TARGET_AGENT_ID."

[[ "$EXISTING_AGENT_NAME" == "$TARGET_AGENT_NAME" ]] || \
    fail "Imported client.keys name is $EXISTING_AGENT_NAME instead of $TARGET_AGENT_NAME."

set_manager_configuration "$MANAGER_ADDRESS" "$MANAGER_PORT" "$PROTOCOL"

if [[ -x "$AGENTD_TEST" ]]; then
    "$AGENTD_TEST" -t
fi

install -d -m 700 "$CYRP_SECRET_DIR"
printf '%s' "$AGENT_TOKEN" > "$CYRP_AGENT_TOKEN_FILE"
chmod 600 "$CYRP_AGENT_TOKEN_FILE"

python3 - \
    "$CYRP_STATE_FILE" \
    "$DEVICE_ID" \
    "$INSTALLATION_ID" \
    "$TARGET_AGENT_ID" \
    "$TARGET_AGENT_NAME" \
    "$MANAGER_ADDRESS" \
    "$MANAGER_PORT" \
    "$PROTOCOL" \
    "${EXISTING_AGENT_ID:-}" \
    "${EXPECTED_OLD_AGENT_ID:-}" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

(
    state_path,
    device_id,
    installation_id,
    agent_id,
    agent_name,
    manager_address,
    manager_port,
    protocol,
    current_agent_id,
    expected_old_agent_id,
) = sys.argv[1:]

payload = {
    "version": 1,
    "deviceId": device_id,
    "installationId": installation_id,
    "wazuhAgentId": agent_id,
    "wazuhAgentName": agent_name,
    "managerAddress": manager_address,
    "managerPort": int(manager_port),
    "protocol": protocol,
    "replacedAgentId": expected_old_agent_id or None,
    "configuredAtUtc": datetime.now(timezone.utc).isoformat(),
}

path = Path(state_path)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

rm -f "$AGENT_STATE"

if command -v systemctl >/dev/null 2>&1; then
    systemctl start wazuh-agent
else
    "$WAZUH_ROOT/bin/wazuh-control" start
fi

deadline=$((SECONDS + CONNECTION_TIMEOUT_SECONDS))
connected=0

while (( SECONDS < deadline )); do
    if [[ -f "$AGENT_STATE" ]] && grep -q "^status='connected'" "$AGENT_STATE"; then
        connected=1
        break
    fi

    sleep 3
done

if [[ "$connected" -ne 1 ]]; then
    if [[ -f "$AGENT_LOG" ]]; then
        tail -n 60 "$AGENT_LOG" >&2 || true
    fi

    fail "Agent $TARGET_AGENT_ID did not reach connected state within $CONNECTION_TIMEOUT_SECONDS seconds."
fi

MIGRATION_COMPLETED=1

if [[ "$KEEP_ENROLLMENT_FILE" -eq 0 ]]; then
    rm -f -- "$ENROLLMENT_FILE"
fi

AGENT_TOKEN=""
CLIENT_KEY=""

printf '\n'
printf 'Success: true\n'
printf 'PreviousAgentId: %s\n' "${EXPECTED_OLD_AGENT_ID:-${EXISTING_AGENT_ID:-unknown}}"
printf 'WazuhAgentId: %s\n' "$TARGET_AGENT_ID"
printf 'WazuhAgentName: %s\n' "$TARGET_AGENT_NAME"
printf 'ManagerAddress: %s\n' "$MANAGER_ADDRESS"
printf 'ManagerPort: %s\n' "$MANAGER_PORT"
printf 'Protocol: %s\n' "$PROTOCOL"
printf 'ConnectionStatus: connected\n'
printf 'BackupDirectory: %s\n' "$BACKUP_DIR"
printf 'EnrollmentFileRemoved: %s\n' "$([[ "$KEEP_ENROLLMENT_FILE" -eq 0 ]] && echo true || echo false)"
