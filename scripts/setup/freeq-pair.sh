#!/usr/bin/env bash
# FreeQ automatic peer exchange — no ~/FreeQ folder drop required.
#
# Modes:
#   invite              Create invite via local freeqd API (bundle + code)
#   join                Join invite (bundle file/url + code) → installs peer under ~/.freeq
#   host                Mutual HTTP pair host (reachable node; auto exchange)
#   join-host           Mutual HTTP pair guest (calls host; auto exchange)
#   gateway             Configure gateway_client from gateway peer bundle (URL or file)
#   show                Print local public peer path and received peers
#
# Private keys never leave the machine. Only public peer material is exchanged.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=freeq-paths.sh
source "$SCRIPT_DIR/freeq-paths.sh"

CMD="${1:-}"
shift || true

usage() {
  cat <<'EOF'
FreeQ pair — automatic public peer exchange (no folder drop).

Direct node↔node (one side reachable on a TCP port):
  # On node A (invite host, reachable):
  freeq pair host --code SECRET --port 8791

  # On node B:
  freeq pair join-host --url http://A_PUBLIC_IP:8791 --code SECRET

  Optional: --auto-start to render config and start freeqd after exchange.

Direct via API invite (bundle can be piped/curl'd; code out-of-band or same channel):
  freeq pair invite [--endpoint HOST:51820]
  freeq pair join --invite-file invite.json --code CODE
  freeq pair join --invite-url https://.../invite.json --code CODE

Gateway leaf (no leaf↔leaf peer.env needed; only gateway public material):
  freeq pair gateway \
    --gateway-endpoint 18.x.x.x:51820 \
    --gateway-peer-env /path/or/url \
    --remote-overlay 10.66.0.2/32 \
    --auto-start

Show state:
  freeq pair show

Orchestrated SSH (zero human file trade when you have SSH to both):
  scripts/setup/freeq-orchestrate-macos.sh --mode direct --remote user@host
  scripts/setup/freeq-orchestrate-macos.sh --mode gateway --remote user@leaf --gateway user@gw \
    --gateway-endpoint IP:51820

State lives under ~/.freeq/ (not ~/FreeQ drop folders).
EOF
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }

api_post() {
  local path="$1" body="$2"
  curl -fsS --max-time 10 \
    -H 'Content-Type: application/json' \
    -d "$body" \
    "${FREEQ_API}${path}"
}

ensure_daemon() {
  if ! curl -fsS --max-time 2 "${FREEQ_API}/v1/status" >/dev/null 2>&1; then
    echo "FreeQ local API is not reachable at $FREEQ_API" >&2
    echo "Run install/setup first so freeqd is listening on 127.0.0.1:6789." >&2
    exit 1
  fi
}

install_peer_env_content() {
  local name="$1" content="$2"
  freeq_ensure_dirs
  local dest="$FREEQ_PEERS_RECEIVED/${name}-peer.env"
  printf '%s\n' "$content" >"$dest"
  # Legacy mirror (optional compatibility)
  printf '%s\n' "$content" >"$FREEQ_LEGACY_RECEIVE/${name}-peer.env" 2>/dev/null || true
  echo "$dest"
}

cmd_show() {
  freeq_ensure_dirs
  echo "FreeQ pair state"
  echo "  FREEQ_HOME:        $FREEQ_HOME"
  echo "  Local node.env:    $FREEQ_LOCAL_ENV $([ -f "$FREEQ_LOCAL_ENV" ] && echo OK || echo MISSING)"
  echo "  Local peer.env:    $FREEQ_LOCAL_PEER_ENV $([ -f "$FREEQ_LOCAL_PEER_ENV" ] && echo OK || echo MISSING)"
  echo "  Received peers:    $FREEQ_PEERS_RECEIVED"
  freeq_find_peer_envs | sed 's/^/    /' || echo "    (none)"
  if curl -fsS --max-time 2 "${FREEQ_API}/v1/status" >/dev/null 2>&1; then
    echo "  Local API:         up"
  else
    echo "  Local API:         down"
  fi
}

cmd_invite() {
  need curl
  ensure_daemon
  freeq_ensure_dirs
  local endpoint=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --endpoint) endpoint="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  local body='{}'
  if [ -n "$endpoint" ]; then
    body="$(python3 -c 'import json,sys; print(json.dumps({"endpoint":sys.argv[1]}))' "$endpoint")"
  fi
  local resp
  resp="$(api_post /v1/invites "$body")"
  local invite_path="$FREEQ_PAIR_DIR/invite-latest.json"
  local code_path="$FREEQ_PAIR_DIR/invite-code-latest.txt"
  python3 - "$resp" "$invite_path" "$code_path" <<'PY'
import json, sys
from pathlib import Path
resp = json.loads(sys.argv[1])
bundle = resp["bundle_text"]
Path(sys.argv[2]).write_text(bundle if bundle.endswith("\n") else bundle + "\n", encoding="utf-8")
code = resp["pairing_code_display"].strip()
Path(sys.argv[3]).write_text(code + "\n", encoding="utf-8")
print(code)
print(resp.get("expires_at", ""))
PY
  local code expires
  code="$(sed -n '1p' "$code_path")"
  expires="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("expires_at",""))' "$resp")"
  echo ""
  echo "Invite created (public material only)."
  echo "  Bundle:  $invite_path"
  echo "  Code:    $code"
  echo "  Expires: $expires"
  echo ""
  echo "On the other node (no folder drop):"
  echo "  freeq pair join --invite-file $invite_path --code $code --auto-start"
}

cmd_join() {
  need curl
  ensure_daemon
  freeq_ensure_dirs
  local invite_file="" invite_url="" code="" auto_start=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --invite-file) invite_file="$2"; shift 2 ;;
      --invite-url) invite_url="$2"; shift 2 ;;
      --code) code="$2"; shift 2 ;;
      --auto-start) auto_start=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$code" ]; then
    echo "--code is required" >&2
    exit 1
  fi
  local bundle_text=""
  if [ -n "$invite_url" ]; then
    bundle_text="$(curl -fsS --max-time 30 "$invite_url")"
  elif [ -n "$invite_file" ]; then
    bundle_text="$(cat "$invite_file")"
  else
    echo "need --invite-file or --invite-url" >&2
    exit 1
  fi
  local body
  body="$(python3 -c 'import json,sys; print(json.dumps({"bundle_text":sys.argv[1],"pairing_code":sys.argv[2]}))' "$bundle_text" "$code")"
  local resp
  resp="$(api_post /v1/invites/join "$body")"
  python3 -c 'import json,sys; r=json.loads(sys.argv[1]);
print(r.get("message",""));
print(r.get("peer_file_path") or "");
print(r.get("accepted"))' "$resp"
  local accepted
  accepted="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("accepted"))' "$resp")"
  if [ "$accepted" != "True" ] && [ "$accepted" != "true" ]; then
    exit 1
  fi
  # API installs under peer_receive_dir; ensure symlink to FREEQ_PEER_ENV default
  local peer_path
  peer_path="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("peer_file_path") or "")' "$resp")"
  if [ -n "$peer_path" ] && [ -f "$peer_path" ]; then
    # also copy into canonical if API still wrote elsewhere
    local name
    name="$(basename "$peer_path")"
    cp "$peer_path" "$FREEQ_PEERS_RECEIVED/$name" 2>/dev/null || true
    export FREEQ_PEER_ENV="$FREEQ_PEERS_RECEIVED/$name"
    if [ ! -f "$FREEQ_PEER_ENV" ]; then
      export FREEQ_PEER_ENV="$peer_path"
    fi
  fi
  if [ "$auto_start" -eq 1 ]; then
    echo "Starting FreeQ with received peer..."
    "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "${FREEQ_PEER_ENV:-$peer_path}"
  fi
}

# ---- Mutual HTTP exchange (true auto, no file trading) ----
# Host listens; guest posts its public peer.env and receives host's in return.
# Auth: shared --code on every request (Bearer).

read_local_public_peer_env() {
  if [ -f "$FREEQ_LOCAL_PEER_ENV" ]; then
    cat "$FREEQ_LOCAL_PEER_ENV"
    return 0
  fi
  if [ -f "$FREEQ_PERF_DIR/peer.env" ]; then
    cat "$FREEQ_PERF_DIR/peer.env"
    return 0
  fi
  echo "Local public peer.env missing. Run freeq setup / install first." >&2
  exit 1
}

cmd_host() {
  need python3
  freeq_ensure_dirs
  local code="" port=8791 auto_start=0 bind="0.0.0.0"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --code) code="$2"; shift 2 ;;
      --port) port="$2"; shift 2 ;;
      --bind) bind="$2"; shift 2 ;;
      --auto-start) auto_start=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$code" ]; then
    code="$(python3 -c 'import secrets; print(secrets.token_hex(4).upper())')"
  fi
  local host_peer
  host_peer="$(read_local_public_peer_env)"
  local guest_out="$FREEQ_PAIR_DIR/guest-peer.env"
  echo "FreeQ pair host listening on ${bind}:${port}"
  echo "  Pair code: $code"
  echo "  Waiting for one guest (Ctrl+C to cancel)..."
  echo "On the other node:"
  echo "  freeq pair join-host --url http://THIS_HOST_IP:${port} --code $code --auto-start"

  FREEQ_PAIR_CODE="$code" \
  FREEQ_PAIR_HOST_PEER="$host_peer" \
  FREEQ_PAIR_GUEST_OUT="$guest_out" \
  FREEQ_PAIR_BIND="$bind" \
  FREEQ_PAIR_PORT="$port" \
  python3 <<'PY'
import os, json
from http.server import BaseHTTPRequestHandler, HTTPServer

CODE = os.environ["FREEQ_PAIR_CODE"].encode()
HOST_PEER = os.environ["FREEQ_PAIR_HOST_PEER"].encode()
GUEST_OUT = os.environ["FREEQ_PAIR_GUEST_OUT"]
BIND = os.environ.get("FREEQ_PAIR_BIND", "0.0.0.0")
PORT = int(os.environ.get("FREEQ_PAIR_PORT", "8791"))
done = {"ok": False}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return
    def _auth(self):
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {CODE.decode()}" or self.headers.get("X-FreeQ-Pair-Code") == CODE.decode()
    def do_GET(self):
        if self.path.rstrip("/") != "/v1/pair/host-peer":
            self.send_error(404); return
        if not self._auth():
            self.send_error(401); return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(HOST_PEER if HOST_PEER.endswith(b"\n") else HOST_PEER + b"\n")
    def do_POST(self):
        if self.path.rstrip("/") != "/v1/pair/guest-peer":
            self.send_error(404); return
        if not self._auth():
            self.send_error(401); return
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        if b"FREEQ_PUBLIC_KEY_B64" not in body or b"FREEQ_NODE_NAME" not in body:
            self.send_error(400, "invalid peer env"); return
        open(GUEST_OUT, "wb").write(body if body.endswith(b"\n") else body + b"\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"accepted": True}).encode())
        done["ok"] = True

httpd = HTTPServer((BIND, PORT), H)
while not done["ok"]:
    httpd.handle_request()
print("guest peer received:", GUEST_OUT)
PY

  # Install guest peer into received
  local guest_name
  guest_name="$(awk -F= '/^FREEQ_NODE_NAME=/{gsub(/['\''"]/,"",$2); print $2; exit}' "$guest_out")"
  guest_name="${guest_name:-remote}"
  local installed
  installed="$(install_peer_env_content "$guest_name" "$(cat "$guest_out")")"
  echo "Installed guest peer: $installed"
  export FREEQ_PEER_ENV="$installed"
  if [ "$auto_start" -eq 1 ]; then
    "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "$installed"
  else
    echo "Next: freeq pair connect --peer-env $installed"
    echo "  or: freeq gateway   # if using connect helper"
  fi
}

cmd_join_host() {
  need curl
  freeq_ensure_dirs
  local url="" code="" auto_start=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --url) url="$2"; shift 2 ;;
      --code) code="$2"; shift 2 ;;
      --auto-start) auto_start=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$url" ] || [ -z "$code" ]; then
    echo "--url and --code required" >&2
    exit 1
  fi
  url="${url%/}"
  local my_peer host_peer
  my_peer="$(read_local_public_peer_env)"
  host_peer="$(curl -fsS --max-time 30 \
    -H "Authorization: Bearer ${code}" \
    -H "X-FreeQ-Pair-Code: ${code}" \
    "${url}/v1/pair/host-peer")"
  curl -fsS --max-time 30 \
    -H "Authorization: Bearer ${code}" \
    -H "X-FreeQ-Pair-Code: ${code}" \
    -H "Content-Type: text/plain" \
    --data-binary "$my_peer" \
    "${url}/v1/pair/guest-peer" >/dev/null
  local host_name
  host_name="$(printf '%s\n' "$host_peer" | awk -F= '/^FREEQ_NODE_NAME=/{gsub(/['\''"]/,"",$2); print $2; exit}')"
  host_name="${host_name:-host}"
  local installed
  installed="$(install_peer_env_content "$host_name" "$host_peer")"
  echo "Installed host peer: $installed"
  export FREEQ_PEER_ENV="$installed"
  if [ "$auto_start" -eq 1 ]; then
    "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "$installed"
  else
    echo "Next: freeq pair connect --peer-env $installed"
  fi
}

cmd_gateway() {
  freeq_ensure_dirs
  local gw_endpoint="" gw_peer="" gw_url="" remote_overlays="" auto_start=0 mode="gateway_client"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --gateway-endpoint) gw_endpoint="$2"; shift 2 ;;
      --gateway-peer-env) gw_peer="$2"; shift 2 ;;
      --gateway-peer-url) gw_url="$2"; shift 2 ;;
      --remote-overlay) remote_overlays="${remote_overlays:+$remote_overlays,}$2"; shift 2 ;;
      --auto-start) auto_start=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$gw_endpoint" ]; then
    echo "--gateway-endpoint HOST:PORT is required" >&2
    exit 1
  fi
  local content=""
  if [ -n "$gw_url" ]; then
    need curl
    content="$(curl -fsS --max-time 60 "$gw_url")"
  elif [ -n "$gw_peer" ]; then
    if [[ "$gw_peer" == http://* || "$gw_peer" == https://* ]]; then
      need curl
      content="$(curl -fsS --max-time 60 "$gw_peer")"
    else
      content="$(cat "$gw_peer")"
    fi
  else
    echo "need --gateway-peer-env PATH|URL or --gateway-peer-url URL" >&2
    exit 1
  fi
  # Normalize endpoint into env content
  if ! printf '%s\n' "$content" | grep -q '^FREEQ_PUBLIC_ENDPOINT='; then
    content="${content}
FREEQ_PUBLIC_ENDPOINT='${gw_endpoint}'
"
  else
    content="$(printf '%s\n' "$content" | python3 -c "
import sys
ep=sys.argv[1]
for line in sys.stdin:
    if line.startswith('FREEQ_PUBLIC_ENDPOINT='):
        print(\"FREEQ_PUBLIC_ENDPOINT='\"+ep+\"'\")
    else:
        sys.stdout.write(line)
" "$gw_endpoint")"
  fi
  local gw_name
  gw_name="$(printf '%s\n' "$content" | awk -F= '/^FREEQ_NODE_NAME=/{gsub(/['\''"]/,"",$2); print $2; exit}')"
  gw_name="${gw_name:-aws-gateway}"
  local installed
  installed="$(install_peer_env_content "$gw_name" "$content")"
  echo "Installed gateway peer: $installed"
  echo "  endpoint: $gw_endpoint"
  echo "  remote overlays: ${remote_overlays:-none}"

  if [ "$auto_start" -eq 1 ]; then
    if [ -x "$SCRIPT_DIR/../field/freeq-leaf-connect-gateway-macos.sh" ]; then
      if [ -z "$remote_overlays" ]; then
        echo "--remote-overlay is required with --auto-start for gateway mode" >&2
        exit 1
      fi
      "$SCRIPT_DIR/../field/freeq-leaf-connect-gateway-macos.sh" \
        --gateway-peer-env "$installed" \
        --remote-overlay "$remote_overlays"
    else
      # Fallback: connect helper treats peer as direct; set EXTRA allowed
      export FREEQ_PEER_ENV="$installed"
      export FREEQ_EXTRA_ALLOWED_IPS="$remote_overlays"
      # Prefer render with gateway_client — freeq-leaf-connect is better; try pair-render
      if [ -x "$SCRIPT_DIR/freeq-render-gateway-client.sh" ]; then
        "$SCRIPT_DIR/freeq-render-gateway-client.sh" \
          --gateway-peer-env "$installed" \
          --remote-overlay "$remote_overlays" \
          --output "$FREEQ_CONFIG"
        "$SCRIPT_DIR/freeq-start-macos.sh" --restart --config "$FREEQ_CONFIG" --peer-env "$installed"
      else
        "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "$installed"
      fi
    fi
  else
    echo "Next (gateway leaf):"
    echo "  freeq pair gateway --gateway-endpoint $gw_endpoint --gateway-peer-env $installed \\"
    echo "    --remote-overlay OTHER_LEAF/32 --auto-start"
  fi
}

cmd_connect() {
  local peer_env=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --peer-env) peer_env="$2"; shift 2 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$peer_env" ]; then
    # pick single received peer if unambiguous
    peers=()
  while IFS= read -r _p; do peers+=("$_p"); done < <(freeq_find_peer_envs || true)
    if [ "${#peers[@]}" -eq 1 ]; then
      peer_env="${peers[0]}"
    else
      echo "pass --peer-env PATH (received peers under $FREEQ_PEERS_RECEIVED)" >&2
      freeq_find_peer_envs || true
      exit 1
    fi
  fi
  "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "$peer_env"
}

case "$CMD" in
  show|"") cmd_show "$@" ;;
  invite) cmd_invite "$@" ;;
  join) cmd_join "$@" ;;
  host) cmd_host "$@" ;;
  join-host) cmd_join_host "$@" ;;
  gateway) cmd_gateway "$@" ;;
  connect) cmd_connect "$@" ;;
  help|-h|--help) usage ;;
  *) echo "Unknown command: $CMD" >&2; usage >&2; exit 1 ;;
esac
