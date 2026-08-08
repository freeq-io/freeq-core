#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

MODE=""
REMOTE=""
GATEWAY=""
SSH_PORT="22"
REMOTE_SSH_PORT=""
GATEWAY_SSH_PORT=""
LOCAL_ENDPOINT=""
REMOTE_ENDPOINT=""
GATEWAY_ENDPOINT=""
LOCAL_OVERLAY=""
REMOTE_OVERLAY=""
GATEWAY_OVERLAY=""
LOCAL_NAME=""
REMOTE_NAME=""
GATEWAY_NAME=""
REMOTE_REPO_DIR="~/freeq-core"
GATEWAY_REPO_DIR="~/freeq-core"
LOCAL_REPO_DIR="$REPO_ROOT"
WORK_DIR="${FREEQ_ORCHESTRATE_DIR:-$HOME/.freeq/orchestrator}"
DRY_RUN=0
SYNC_SOURCE=0
PING_COUNT="${FREEQ_PING_COUNT:-3}"
SSH_PASSWORD_ONLY=0

usage() {
  cat <<'EOF'
FreeQ SSH orchestrator for macOS.

This is the no-file-trading setup path. Run it from the controlling Mac. It
uses SSH to install/prepare the remote node or gateway, exchanges public peer
identity files automatically, renders explicit configs, restarts FreeQ on every
host, and prints one PASS/FAIL result.

Direct node-to-node on the same LAN:
  scripts/setup/freeq-orchestrate-macos.sh \
    --mode direct \
    --remote tester@192.168.1.63

Direct node-to-node over public internet:
  scripts/setup/freeq-orchestrate-macos.sh \
    --mode direct \
    --remote tester@remote.example.com \
    --local-endpoint 136.46.40.139:51820 \
    --remote-endpoint 203.0.113.20:51820

Gateway relay for hostile NAT:
  scripts/setup/freeq-orchestrate-macos.sh \
    --mode gateway \
    --remote tester@leaf2.example.com \
    --gateway ubuntu@gateway.example.com \
    --gateway-endpoint 18.225.246.90:51820

Options:
  --mode direct|gateway      topology to configure
  --remote USER@HOST         remote leaf node reachable over SSH
  --gateway USER@HOST        gateway host reachable over SSH (gateway mode)
  --ssh-port PORT            default SSH port for remote/gateway, default 22
  --remote-ssh-port PORT     SSH port for --remote
  --gateway-ssh-port PORT    SSH port for --gateway
  --local-endpoint HOST:PORT endpoint the remote can use to dial this Mac
                              direct mode defaults to this Mac's en0 IP:51820
  --remote-endpoint HOST:PORT endpoint this Mac can use to dial the remote
                              direct mode defaults to the SSH host:51820
  --gateway-endpoint HOST:PORT gateway UDP endpoint leaves can dial
  --local-overlay CIDR       local overlay, defaults to local setup identity
  --remote-overlay CIDR      remote overlay, defaults to remote setup identity
  --gateway-overlay CIDR     gateway overlay, defaults to remote setup identity
  --local-name NAME          local node name override
  --remote-name NAME         remote node name override
  --gateway-name NAME        gateway node name override
  --remote-repo-dir PATH     remote freeq-core path, default ~/freeq-core
  --gateway-repo-dir PATH    gateway freeq-core path, default ~/freeq-core
  --sync-source              copy this checkout to missing remote repo dirs
  --ssh-password-only        disable public-key auth so SSH prompts for password
  --dry-run                  print plan and validate arguments only
  --help, -h                 show this help

Authentication:
  The script asks SSH/sudo to authenticate when needed. Use a normal Terminal so
  SSH and sudo can prompt. No private FreeQ key is copied between machines.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --remote) REMOTE="$2"; shift 2 ;;
    --gateway) GATEWAY="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --remote-ssh-port) REMOTE_SSH_PORT="$2"; shift 2 ;;
    --gateway-ssh-port) GATEWAY_SSH_PORT="$2"; shift 2 ;;
    --local-endpoint) LOCAL_ENDPOINT="$2"; shift 2 ;;
    --remote-endpoint) REMOTE_ENDPOINT="$2"; shift 2 ;;
    --gateway-endpoint) GATEWAY_ENDPOINT="$2"; shift 2 ;;
    --local-overlay) LOCAL_OVERLAY="$2"; shift 2 ;;
    --remote-overlay) REMOTE_OVERLAY="$2"; shift 2 ;;
    --gateway-overlay) GATEWAY_OVERLAY="$2"; shift 2 ;;
    --local-name) LOCAL_NAME="$2"; shift 2 ;;
    --remote-name) REMOTE_NAME="$2"; shift 2 ;;
    --gateway-name) GATEWAY_NAME="$2"; shift 2 ;;
    --remote-repo-dir) REMOTE_REPO_DIR="$2"; shift 2 ;;
    --gateway-repo-dir) GATEWAY_REPO_DIR="$2"; shift 2 ;;
    --sync-source) SYNC_SOURCE=1; shift ;;
    --ssh-password-only) SSH_PASSWORD_ONLY=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

REMOTE_SSH_PORT="${REMOTE_SSH_PORT:-$SSH_PORT}"
GATEWAY_SSH_PORT="${GATEWAY_SSH_PORT:-$SSH_PORT}"

fail() {
  echo "" >&2
  echo "FreeQ orchestration result: FAIL" >&2
  echo "$*" >&2
  exit 1
}

pass() {
  echo ""
  echo "FreeQ orchestration result: PASS"
  echo "$*"
}

step() {
  echo ""
  echo "== $* =="
}

need() {
  command -v "$1" >/dev/null 2>&1
}

quote_shell() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

env_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '
    index($0, key "=") == 1 {
      value = substr($0, length(key) + 2)
      if (value ~ /^'\''.*'\''$/) {
        value = substr(value, 2, length(value) - 2)
      }
      print value
      exit
    }
  ' "$file"
}

validate_mode() {
  case "$MODE" in
    direct|gateway) ;;
    "") fail "--mode is required: direct or gateway" ;;
    *) fail "--mode must be direct or gateway, got: $MODE" ;;
  esac
}

validate_port() {
  local value="$1"
  local label="$2"
  [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || \
    fail "$label must be a TCP port from 1 through 65535, got: $value"
}

validate_endpoint() {
  local endpoint="$1"
  local label="$2"
  case "$endpoint" in
    ""|*REPLACE*|*PLACEHOLDER*|*HOST_OR_IP*|*ACTUAL_*|*YOUR_HOST*|*PEER_HOST*|*peer-host*|*"<"*|*">"*)
      fail "$label must be a real HOST:PORT endpoint, got: ${endpoint:-blank}"
      ;;
  esac
  if [[ "$endpoint" != *:* ]]; then
    fail "$label must be HOST:PORT, got: $endpoint"
  fi
  local host="${endpoint%:*}"
  local port="${endpoint##*:}"
  if [ -z "$host" ] || [ -z "$port" ] || ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    fail "$label must be HOST:PORT with port 1-65535, got: $endpoint"
  fi
}

endpoint_host() {
  printf '%s\n' "${1%:*}"
}

endpoint_port() {
  printf '%s\n' "${1##*:}"
}

ssh_host() {
  local target="$1"
  local host="${target##*@}"
  printf '%s\n' "$host"
}

local_lan_ip() {
  if [ -x /usr/sbin/ipconfig ]; then
    /usr/sbin/ipconfig getifaddr en0 2>/dev/null && return 0
  fi
  if command -v ipconfig >/dev/null 2>&1; then
    ipconfig getifaddr en0 2>/dev/null && return 0
  fi
  if [ -x /sbin/ifconfig ]; then
    /sbin/ifconfig en0 inet 2>/dev/null | awk '/inet / { print $2; exit }'
  fi
}

validate_overlay() {
  local value="$1"
  local label="$2"
  python3 - "$value" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
if network.version != 4:
    raise SystemExit(1)
PY
  local status=$?
  [ "$status" -eq 0 ] || fail "$label must be an IPv4 CIDR such as 10.66.0.63/24, got: $value"
}

overlay_ip() {
  python3 - "$1" <<'PY'
import sys
print(sys.argv[1].split("/", 1)[0])
PY
}

resolve_endpoint_local() {
  local endpoint="$1"
  local label="$2"
  python3 - "$endpoint" "$label" <<'PY'
import socket
import sys

endpoint, label = sys.argv[1], sys.argv[2]
host, _, port = endpoint.rpartition(":")
try:
    infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
except Exception as exc:
    print(f"{label} did not resolve on this host: {endpoint} ({exc})", file=sys.stderr)
    raise SystemExit(1)
if not infos:
    print(f"{label} did not resolve to an IPv4 address: {endpoint}", file=sys.stderr)
    raise SystemExit(1)
print(f"{infos[0][4][0]}:{port}")
PY
}

ssh_base() {
  local port="$1"
  shift
  local extra_opts=()
  if [ "$SSH_PASSWORD_ONLY" -eq 1 ]; then
    extra_opts+=(-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive)
  fi
  ssh -p "$port" \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2 \
    -o ControlMaster=auto \
    -o ControlPersist=10m \
    ${extra_opts[@]+"${extra_opts[@]}"} \
    "$@"
}

scp_to() {
  local port="$1"
  local src="$2"
  local dest="$3"
  echo "SCP upload: $src -> $dest" >&2
  local extra_opts=()
  if [ "$SSH_PASSWORD_ONLY" -eq 1 ]; then
    extra_opts+=(-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive)
  fi
  scp -P "$port" \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2 \
    -o ControlMaster=auto \
    -o ControlPersist=10m \
    ${extra_opts[@]+"${extra_opts[@]}"} \
    "$src" "$dest"
}

scp_from() {
  local port="$1"
  local src="$2"
  local dest="$3"
  echo "SCP download: $src -> $dest" >&2
  local extra_opts=()
  if [ "$SSH_PASSWORD_ONLY" -eq 1 ]; then
    extra_opts+=(-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive)
  fi
  scp -P "$port" \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2 \
    -o ControlMaster=auto \
    -o ControlPersist=10m \
    ${extra_opts[@]+"${extra_opts[@]}"} \
    "$src" "$dest"
}

remote_run() {
  local target="$1"
  local port="$2"
  local command_text="$3"
  echo "SSH: $target:$port" >&2
  ssh_base "$port" "$target" "$command_text"
}

remote_run_tty() {
  local target="$1"
  local port="$2"
  local command_text="$3"
  echo "SSH TTY: $target:$port" >&2
  local extra_opts=()
  if [ "$SSH_PASSWORD_ONLY" -eq 1 ]; then
    extra_opts+=(-o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive)
  fi
  ssh -tt -p "$port" \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2 \
    -o ControlMaster=auto \
    -o ControlPersist=10m \
    ${extra_opts[@]+"${extra_opts[@]}"} \
    "$target" "$command_text"
}

remote_uname() {
  local target="$1"
  local port="$2"
  remote_run "$target" "$port" "uname -s"
}

require_remote_darwin() {
  local target="$1"
  local port="$2"
  local role="$3"
  local os_name
  if ! os_name="$(remote_uname "$target" "$port")"; then
    local host
    host="$(ssh_host "$target")"
    if [[ "$host" == *.local ]] || [[ "$host" != *.* ]]; then
      fail "SSH connection failed for $role host $target on port $port. This Mac could not resolve that local name. On the remote Mac, run 'ipconfig getifaddr en0' and rerun with USER@LAN_IP."
    fi
    fail "SSH connection failed for $role host $target on port $port. Use a resolvable host/IP and verify SSH is enabled."
  fi
  [ "$os_name" = "Darwin" ] || fail "$role host $target is $os_name. This orchestrator can start macOS nodes only. Linux gateway activation must use the Linux/systemd path before gateway mode can be supported end to end."
}

remote_resolve_endpoint() {
  local target="$1"
  local port="$2"
  local endpoint="$3"
  local label="$4"
  remote_run "$target" "$port" "python3 - $(quote_shell "$endpoint") $(quote_shell "$label") <<'PY'
import socket
import sys
endpoint, label = sys.argv[1], sys.argv[2]
host, _, port = endpoint.rpartition(':')
try:
    infos = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)
except Exception as exc:
    print(f'{label} did not resolve on this host: {endpoint} ({exc})', file=sys.stderr)
    raise SystemExit(1)
if not infos:
    print(f'{label} did not resolve to an IPv4 address: {endpoint}', file=sys.stderr)
    raise SystemExit(1)
print(f'{infos[0][4][0]}:{port}')
PY"
}

ensure_local_dependencies() {
  need ssh || fail "ssh is required on the controlling Mac"
  need scp || fail "scp is required on the controlling Mac"
  need python3 || fail "python3 is required on the controlling Mac"
  need cargo || fail "cargo is required to build FreeQ from this checkout"
}

sync_source_if_needed() {
  local target="$1"
  local port="$2"
  local repo_dir="$3"
  if ! remote_run "$target" "$port" "printf '%s\n' freeq-ssh-ok" >/dev/null; then
    local host
    host="$(ssh_host "$target")"
    if [[ "$host" == *.local ]]; then
      fail "SSH connection failed for $target on port $port. This Mac could not use the .local name. On the remote Mac, run 'ipconfig getifaddr en0' and rerun with USER@LAN_IP instead of $target."
    fi
    fail "SSH connection failed for $target on port $port. Use a resolvable host/IP, verify SSH is enabled, and rerun."
  fi
  if remote_run "$target" "$port" "[ -f $repo_dir/Cargo.toml ] && [ -d $repo_dir/scripts/setup ]"; then
    return 0
  fi
  [ "$SYNC_SOURCE" -eq 1 ] || fail "$target does not have FreeQ at $repo_dir. Rerun with --sync-source or install FreeQ there first."
  step "Syncing source to $target:$repo_dir"
  remote_run "$target" "$port" "mkdir -p $repo_dir"
  tar --exclude .git --exclude target --exclude perf-results -C "$REPO_ROOT" -cf - . | \
    ssh_base "$port" "$target" "tar -C $repo_dir -xf -"
}

local_setup() {
  local endpoint="$1"
  local overlay="$2"
  local name="$3"
  local args=()
  [ -n "$endpoint" ] && args+=(FREEQ_PUBLIC_ENDPOINT="$endpoint")
  [ -n "$overlay" ] && args+=(FREEQ_OVERLAY_ADDRESS="$overlay")
  [ -n "$name" ] && args+=(FREEQ_NODE_NAME="$name")
  step "Preparing local node"
  env FREEQ_ASSUME_DEFAULTS=1 FREEQ_INSTALL_DIR="$LOCAL_REPO_DIR" "${args[@]}" \
    "$SCRIPT_DIR/freeq-setup-macos.sh"
}

remote_setup() {
  local target="$1"
  local port="$2"
  local repo_dir="$3"
  local endpoint="$4"
  local overlay="$5"
  local name="$6"
  local command_text="cd $repo_dir && FREEQ_ASSUME_DEFAULTS=1"
  [ -n "$endpoint" ] && command_text="$command_text FREEQ_PUBLIC_ENDPOINT=$(quote_shell "$endpoint")"
  [ -n "$overlay" ] && command_text="$command_text FREEQ_OVERLAY_ADDRESS=$(quote_shell "$overlay")"
  [ -n "$name" ] && command_text="$command_text FREEQ_NODE_NAME=$(quote_shell "$name")"
  command_text="$command_text bash scripts/setup/freeq-setup-macos.sh"
  step "Preparing $target"
  remote_run "$target" "$port" "$command_text"
}

copy_peer_from_remote() {
  local target="$1"
  local port="$2"
  local repo_label="$3"
  local dest="$4"
  remote_run "$target" "$port" "ls -1 ~/FreeQ/01-send-this-file/*-peer.env | head -1" > "$WORK_DIR/$repo_label-peer-path.txt"
  local remote_peer_path
  remote_peer_path="$(sed -n '1p' "$WORK_DIR/$repo_label-peer-path.txt")"
  [ -n "$remote_peer_path" ] || fail "could not locate peer file on $target"
  scp_from "$port" "$target:$remote_peer_path" "$dest"
}

copy_peer_to_remote() {
  local target="$1"
  local port="$2"
  local src="$3"
  remote_run "$target" "$port" "mkdir -p ~/.freeq/orchestrator"
  scp_to "$port" "$src" "$target:~/.freeq/orchestrator/$(basename "$src")"
}

local_peer_file() {
  ls -1 "$HOME/FreeQ/01-send-this-file/"*-peer.env | head -1
}

write_config_from_envs() {
  local output="$1"
  local local_env="$2"
  local local_key_path="$3"
  shift 3
  local node_name node_address node_listen
  node_name="$(env_value "$local_env" FREEQ_NODE_NAME)"
  node_address="$(env_value "$local_env" FREEQ_NODE_ADDRESS)"
  node_listen="$(env_value "$local_env" FREEQ_NODE_LISTEN)"
  mkdir -p "$(dirname "$output")"
  python3 - "$output" "$node_name" "$node_address" "$node_listen" "$local_key_path" "$@" <<'PY'
import json
import sys
from pathlib import Path

output, node_name, node_address, node_listen, key_path, *peer_specs = sys.argv[1:]
lines = [
    "[node]",
    f"name = {json.dumps(node_name)}",
    f"listen = {json.dumps(node_listen)}",
    f"address = {json.dumps(node_address)}",
    f"key_path = {json.dumps(key_path)}",
    'algorithm = "ml-kem-768"',
    'sign = "ml-dsa-65"',
    "api_enabled = true",
    'api_addr = "127.0.0.1:6789"',
]
for spec in peer_specs:
    name, endpoint, public_key, kem_key, mode, allowed_csv = spec.split("\t")
    allowed_ips = [value for value in allowed_csv.split(",") if value]
    lines.extend([
        "",
        "[[peer]]",
        f"name = {json.dumps(name)}",
    ])
    if endpoint:
        lines.append(f"endpoint = {json.dumps(endpoint)}")
    lines.extend([
        f"public_key = {json.dumps(public_key)}",
        f"kem_key = {json.dumps(kem_key)}",
    ])
    if mode:
        lines.append(f"mode = {json.dumps(mode)}")
    lines.append("allowed_ips = [" + ", ".join(json.dumps(value) for value in allowed_ips) + "]")
    lines.append("key_rotation_secs = 900")
Path(output).write_text("\n".join(lines) + "\n")
PY
}

peer_spec() {
  local peer_env="$1"
  local endpoint="$2"
  local mode="$3"
  local allowed_ips="$4"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(env_value "$peer_env" FREEQ_NODE_NAME)" \
    "$endpoint" \
    "$(env_value "$peer_env" FREEQ_PUBLIC_KEY_B64)" \
    "$(env_value "$peer_env" FREEQ_KEM_KEY_B64)" \
    "$mode" \
    "$allowed_ips"
}

remote_peer_spec_command() {
  local peer_path="$1"
  local endpoint="$2"
  local mode="$3"
  local allowed_ips="$4"
  cat <<EOF
awk -v endpoint=$(quote_shell "$endpoint") -v mode=$(quote_shell "$mode") -v allowed=$(quote_shell "$allowed_ips") '
  function value(key) {
    prefix = key "="
    if (index(\$0, prefix) == 1) {
      raw = substr(\$0, length(prefix) + 1)
      if (raw ~ /^'\''.*'\''$/) raw = substr(raw, 2, length(raw) - 2)
      values[key] = raw
    }
  }
  { value("FREEQ_NODE_NAME"); value("FREEQ_PUBLIC_KEY_B64"); value("FREEQ_KEM_KEY_B64") }
  END {
    printf "%s\t%s\t%s\t%s\t%s\t%s\n", values["FREEQ_NODE_NAME"], endpoint, values["FREEQ_PUBLIC_KEY_B64"], values["FREEQ_KEM_KEY_B64"], mode, allowed
  }
' $peer_path
EOF
}

remote_write_config_command() {
  local output="$1"
  local local_env="$2"
  local key_path="$3"
  shift 3
  local specs=("$@")
  local spec_args=""
  local spec
  for spec in "${specs[@]}"; do
    spec_args="$spec_args $(quote_shell "$spec")"
  done
  cat <<EOF
mkdir -p \$(dirname $output)
python3 - $output $local_env $key_path $spec_args <<'PY'
import json
import sys
from pathlib import Path

output, local_env, key_path, *peer_specs = sys.argv[1:]
values = {}
for raw in Path(local_env).read_text().splitlines():
    if "=" not in raw or raw.startswith("#"):
        continue
    key, value = raw.split("=", 1)
    if value.startswith("'") and value.endswith("'"):
        value = value[1:-1]
    values[key] = value
lines = [
    "[node]",
    f"name = {json.dumps(values['FREEQ_NODE_NAME'])}",
    f"listen = {json.dumps(values['FREEQ_NODE_LISTEN'])}",
    f"address = {json.dumps(values['FREEQ_NODE_ADDRESS'])}",
    f"key_path = {json.dumps(key_path)}",
    'algorithm = "ml-kem-768"',
    'sign = "ml-dsa-65"',
    "api_enabled = true",
    'api_addr = "127.0.0.1:6789"',
]
for spec in peer_specs:
    name, endpoint, public_key, kem_key, mode, allowed_csv = spec.split("\t")
    allowed_ips = [value for value in allowed_csv.split(",") if value]
    lines.extend(["", "[[peer]]", f"name = {json.dumps(name)}"])
    if endpoint:
        lines.append(f"endpoint = {json.dumps(endpoint)}")
    lines.extend([f"public_key = {json.dumps(public_key)}", f"kem_key = {json.dumps(kem_key)}"])
    if mode:
        lines.append(f"mode = {json.dumps(mode)}")
    lines.append("allowed_ips = [" + ", ".join(json.dumps(value) for value in allowed_ips) + "]")
    lines.append("key_rotation_secs = 900")
Path(output).write_text("\n".join(lines) + "\n")
PY
EOF
}

verify_peer_env_complete() {
  local file="$1"
  "$SCRIPT_DIR/freeq-validate-peer-env.sh" --allow-missing-endpoint "$file" >/dev/null || fail "peer file validation failed: $file"
}

local_start() {
  local peer_env="$1"
  local extra_allowed="$2"
  local config="$3"
  step "Starting local FreeQ"
  FREEQ_EXTRA_ALLOWED_IPS="$extra_allowed" "$SCRIPT_DIR/freeq-start-macos.sh" \
    --restart --config "$config" --peer-env "$peer_env"
}

remote_start() {
  local target="$1"
  local port="$2"
  local repo_dir="$3"
  local peer_env="$4"
  local extra_allowed="$5"
  local config="$6"
  step "Starting FreeQ on $target"
  remote_run_tty "$target" "$port" "cd $repo_dir && FREEQ_EXTRA_ALLOWED_IPS=$(quote_shell "$extra_allowed") scripts/setup/freeq-start-macos.sh --restart --config $config --peer-env $peer_env"
}

remote_ping_overlay() {
  local target="$1"
  local port="$2"
  local ip="$3"
  remote_run "$target" "$port" "ping -c $PING_COUNT $ip"
}

local_ping_overlay() {
  local ip="$1"
  ping -c "$PING_COUNT" "$ip"
}

print_plan() {
  cat <<EOF
FreeQ SSH orchestration plan
  Mode:             $MODE
  Local repo:       $LOCAL_REPO_DIR
  Remote:           ${REMOTE:-not used}
  Remote SSH port:  $REMOTE_SSH_PORT
  Remote repo:      $REMOTE_REPO_DIR
  Gateway:          ${GATEWAY:-not used}
  Gateway SSH port: $GATEWAY_SSH_PORT
  Gateway repo:     $GATEWAY_REPO_DIR
  Local endpoint:   ${LOCAL_ENDPOINT:-auto/unused}
  Remote endpoint:  ${REMOTE_ENDPOINT:-auto/unused}
  Gateway endpoint: ${GATEWAY_ENDPOINT:-unused}
  SSH auth:         $([ "$SSH_PASSWORD_ONLY" -eq 1 ] && printf 'password only' || printf 'default')
  Work dir:         $WORK_DIR
EOF
}

validate_common() {
  validate_mode
  validate_port "$REMOTE_SSH_PORT" "--remote-ssh-port"
  validate_port "$GATEWAY_SSH_PORT" "--gateway-ssh-port"
  [ "$(uname -s)" = "Darwin" ] || fail "the controlling host must be macOS for this orchestrator"
  [ -n "$REMOTE" ] || fail "--remote USER@HOST is required"
  ensure_local_dependencies
  case "$MODE" in
    direct)
      if [ -z "$LOCAL_ENDPOINT" ]; then
        local ip
        ip="$(local_lan_ip)"
        [ -n "$ip" ] || fail "--local-endpoint is required because this Mac's en0 IPv4 address could not be detected"
        LOCAL_ENDPOINT="$ip:51820"
      fi
      if [ -z "$REMOTE_ENDPOINT" ]; then
        REMOTE_ENDPOINT="$(ssh_host "$REMOTE"):51820"
      fi
      validate_endpoint "$LOCAL_ENDPOINT" "--local-endpoint"
      validate_endpoint "$REMOTE_ENDPOINT" "--remote-endpoint"
      ;;
    gateway)
      [ -n "$GATEWAY" ] || fail "--gateway USER@HOST is required in gateway mode"
      validate_endpoint "$GATEWAY_ENDPOINT" "--gateway-endpoint"
      ;;
  esac
  if [ -n "$LOCAL_OVERLAY" ]; then
    validate_overlay "$LOCAL_OVERLAY" "--local-overlay"
  fi
  if [ -n "$REMOTE_OVERLAY" ]; then
    validate_overlay "$REMOTE_OVERLAY" "--remote-overlay"
  fi
  if [ -n "$GATEWAY_OVERLAY" ]; then
    validate_overlay "$GATEWAY_OVERLAY" "--gateway-overlay"
  fi
}

run_direct() {
  mkdir -p "$WORK_DIR/direct"
  require_remote_darwin "$REMOTE" "$REMOTE_SSH_PORT" "remote leaf"
  sync_source_if_needed "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR"

  local resolved_remote resolved_local_for_remote
  step "Resolving endpoints"
  resolved_remote="$(resolve_endpoint_local "$REMOTE_ENDPOINT" "--remote-endpoint")" || fail "local host cannot resolve remote endpoint"
  resolved_local_for_remote="$(remote_resolve_endpoint "$REMOTE" "$REMOTE_SSH_PORT" "$LOCAL_ENDPOINT" "--local-endpoint")" || fail "remote host cannot resolve local endpoint"
  echo "Local will dial remote: $resolved_remote"
  echo "Remote will dial local: $resolved_local_for_remote"

  local_setup "$LOCAL_ENDPOINT" "$LOCAL_OVERLAY" "$LOCAL_NAME"
  remote_setup "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR" "$REMOTE_ENDPOINT" "$REMOTE_OVERLAY" "$REMOTE_NAME"

  local local_peer remote_peer
  local_peer="$(local_peer_file)"
  remote_peer="$WORK_DIR/direct/remote-peer.env"
  copy_peer_from_remote "$REMOTE" "$REMOTE_SSH_PORT" "remote" "$remote_peer"
  verify_peer_env_complete "$local_peer"
  verify_peer_env_complete "$remote_peer"
  copy_peer_to_remote "$REMOTE" "$REMOTE_SSH_PORT" "$local_peer"

  local local_env="$HOME/.freeq/perf/node.env"
  local remote_peer_remote_path="~/.freeq/orchestrator/$(basename "$local_peer")"
  local local_overlay remote_overlay local_ip remote_ip
  local_overlay="$(env_value "$local_env" FREEQ_NODE_ADDRESS)"
  remote_overlay="$(env_value "$remote_peer" FREEQ_NODE_ADDRESS)"
  local_ip="$(overlay_ip "$local_overlay")"
  remote_ip="$(overlay_ip "$remote_overlay")"

  step "Rendering direct configs"
  local remote_spec
  remote_spec="$(peer_spec "$remote_peer" "$resolved_remote" "direct" "$remote_ip/32")"
  write_config_from_envs "$WORK_DIR/direct/local-freeq.toml" "$local_env" "$HOME/.freeq/perf/identity.key" "$remote_spec"
  cp "$WORK_DIR/direct/local-freeq.toml" "$HOME/.freeq/perf/freeq.toml"
  remote_run "$REMOTE" "$REMOTE_SSH_PORT" "$(remote_write_config_command ~/.freeq/perf/freeq.toml ~/.freeq/perf/node.env ~/.freeq/perf/identity.key "$(remote_run "$REMOTE" "$REMOTE_SSH_PORT" "$(remote_peer_spec_command "$remote_peer_remote_path" "$resolved_local_for_remote" "direct" "$local_ip/32")")")"

  remote_start "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR" "$remote_peer_remote_path" "" "~/.freeq/perf/freeq.toml"
  local_start "$remote_peer" "" "$HOME/.freeq/perf/freeq.toml"

  step "Verifying direct overlay"
  local_ping_overlay "$remote_ip" || fail "local node could not ping remote overlay $remote_ip"
  remote_ping_overlay "$REMOTE" "$REMOTE_SSH_PORT" "$local_ip" || fail "remote node could not ping local overlay $local_ip"
  pass "direct node-to-node overlay is configured and bidirectional ping passed"
}

run_gateway() {
  mkdir -p "$WORK_DIR/gateway"
  require_remote_darwin "$REMOTE" "$REMOTE_SSH_PORT" "remote leaf"
  require_remote_darwin "$GATEWAY" "$GATEWAY_SSH_PORT" "gateway"
  sync_source_if_needed "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR"
  sync_source_if_needed "$GATEWAY" "$GATEWAY_SSH_PORT" "$GATEWAY_REPO_DIR"

  local resolved_gateway
  step "Resolving gateway endpoint"
  resolved_gateway="$(resolve_endpoint_local "$GATEWAY_ENDPOINT" "--gateway-endpoint")" || fail "local host cannot resolve gateway endpoint"
  remote_resolve_endpoint "$REMOTE" "$REMOTE_SSH_PORT" "$GATEWAY_ENDPOINT" "--gateway-endpoint" >/dev/null || fail "remote leaf cannot resolve gateway endpoint"
  echo "Leaves will dial gateway: $resolved_gateway"

  local_setup "" "$LOCAL_OVERLAY" "$LOCAL_NAME"
  remote_setup "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR" "" "$REMOTE_OVERLAY" "$REMOTE_NAME"
  remote_setup "$GATEWAY" "$GATEWAY_SSH_PORT" "$GATEWAY_REPO_DIR" "$GATEWAY_ENDPOINT" "$GATEWAY_OVERLAY" "$GATEWAY_NAME"

  local local_peer remote_peer gateway_peer
  local_peer="$(local_peer_file)"
  remote_peer="$WORK_DIR/gateway/remote-peer.env"
  gateway_peer="$WORK_DIR/gateway/gateway-peer.env"
  copy_peer_from_remote "$REMOTE" "$REMOTE_SSH_PORT" "remote" "$remote_peer"
  copy_peer_from_remote "$GATEWAY" "$GATEWAY_SSH_PORT" "gateway" "$gateway_peer"
  verify_peer_env_complete "$local_peer"
  verify_peer_env_complete "$remote_peer"
  verify_peer_env_complete "$gateway_peer"
  copy_peer_to_remote "$REMOTE" "$REMOTE_SSH_PORT" "$local_peer"
  copy_peer_to_remote "$REMOTE" "$REMOTE_SSH_PORT" "$gateway_peer"
  copy_peer_to_remote "$GATEWAY" "$GATEWAY_SSH_PORT" "$local_peer"
  copy_peer_to_remote "$GATEWAY" "$GATEWAY_SSH_PORT" "$remote_peer"

  local local_env="$HOME/.freeq/perf/node.env"
  local local_overlay remote_overlay gateway_overlay local_ip remote_ip gateway_ip
  local_overlay="$(env_value "$local_env" FREEQ_NODE_ADDRESS)"
  remote_overlay="$(env_value "$remote_peer" FREEQ_NODE_ADDRESS)"
  gateway_overlay="$(env_value "$gateway_peer" FREEQ_NODE_ADDRESS)"
  local_ip="$(overlay_ip "$local_overlay")"
  remote_ip="$(overlay_ip "$remote_overlay")"
  gateway_ip="$(overlay_ip "$gateway_overlay")"

  step "Rendering gateway configs"
  local gateway_spec remote_leaf_spec local_leaf_spec remote_spec_for_local local_spec_for_remote
  gateway_spec="$(peer_spec "$gateway_peer" "$resolved_gateway" "gateway_client" "$gateway_ip/32,$remote_ip/32")"
  remote_leaf_spec="$(peer_spec "$remote_peer" "" "relay_leaf" "")"
  write_config_from_envs "$WORK_DIR/gateway/local-freeq.toml" "$local_env" "$HOME/.freeq/perf/identity.key" "$gateway_spec" "$remote_leaf_spec"
  cp "$WORK_DIR/gateway/local-freeq.toml" "$HOME/.freeq/perf/freeq.toml"

  local gateway_peer_remote="~/.freeq/orchestrator/$(basename "$gateway_peer")"
  local local_peer_remote="~/.freeq/orchestrator/$(basename "$local_peer")"
  local remote_peer_gateway="~/.freeq/orchestrator/$(basename "$remote_peer")"
  local local_peer_gateway="~/.freeq/orchestrator/$(basename "$local_peer")"
  remote_spec_for_local="$(remote_run "$REMOTE" "$REMOTE_SSH_PORT" "$(remote_peer_spec_command "$gateway_peer_remote" "$resolved_gateway" "gateway_client" "$gateway_ip/32,$local_ip/32")")"
  local_spec_for_remote="$(remote_run "$REMOTE" "$REMOTE_SSH_PORT" "$(remote_peer_spec_command "$local_peer_remote" "" "relay_leaf" "")")"
  remote_run "$REMOTE" "$REMOTE_SSH_PORT" "$(remote_write_config_command ~/.freeq/perf/freeq.toml ~/.freeq/perf/node.env ~/.freeq/perf/identity.key "$remote_spec_for_local" "$local_spec_for_remote")"

  local gateway_local_leaf_spec gateway_remote_leaf_spec
  gateway_local_leaf_spec="$(remote_run "$GATEWAY" "$GATEWAY_SSH_PORT" "$(remote_peer_spec_command "$local_peer_gateway" "" "relay_leaf" "$local_ip/32")")"
  gateway_remote_leaf_spec="$(remote_run "$GATEWAY" "$GATEWAY_SSH_PORT" "$(remote_peer_spec_command "$remote_peer_gateway" "" "relay_leaf" "$remote_ip/32")")"
  remote_run "$GATEWAY" "$GATEWAY_SSH_PORT" "$(remote_write_config_command ~/.freeq/perf/freeq.toml ~/.freeq/perf/node.env ~/.freeq/perf/identity.key "$gateway_local_leaf_spec" "$gateway_remote_leaf_spec")"

  remote_start "$GATEWAY" "$GATEWAY_SSH_PORT" "$GATEWAY_REPO_DIR" "$local_peer_gateway" "$remote_ip/32" "~/.freeq/perf/freeq.toml"
  remote_start "$REMOTE" "$REMOTE_SSH_PORT" "$REMOTE_REPO_DIR" "$gateway_peer_remote" "$local_ip/32" "~/.freeq/perf/freeq.toml"
  local_start "$gateway_peer" "$remote_ip/32" "$HOME/.freeq/perf/freeq.toml"

  step "Verifying gateway overlay"
  local_ping_overlay "$remote_ip" || fail "local leaf could not ping remote leaf overlay $remote_ip through gateway"
  remote_ping_overlay "$REMOTE" "$REMOTE_SSH_PORT" "$local_ip" || fail "remote leaf could not ping local leaf overlay $local_ip through gateway"
  pass "node-gateway-node overlay is configured and bidirectional ping passed"
}

validate_common
print_plan

if [ "$DRY_RUN" -eq 1 ]; then
  pass "dry run completed; no hosts were changed"
  exit 0
fi

case "$MODE" in
  direct) run_direct ;;
  gateway) run_gateway ;;
esac
