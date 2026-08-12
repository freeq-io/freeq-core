#!/usr/bin/env bash
# FreeQ automatic peer exchange — zero human trading of .env files.
#
# Modes:
#   invite / join       API invite (public bundle + one-time code)
#   host / join-host    Mutual HTTP exchange of PUBLIC peer.env only
#   gateway             Leaf joins gateway via PUBLIC peer URL/path only
#   publish             Serve this node's PUBLIC peer.env over HTTP (for leaves)
#   bootstrap           Fully env-driven auto pair (cloud-init / installers)
#   show / connect      Inspect / start with received public peer
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
FreeQ pair — zero human .env trading (public peer material only).

Direct node↔node (one reachable TCP pair port; no file copy):
  freeq pair host --auto-start
  # prints a one-liner for the other node:
  freeq pair join-host --url http://HOST:8791 --code CODE --auto-start

Gateway leaf (only needs gateway PUBLIC peer URL + endpoint):
  freeq pair gateway \
    --gateway-endpoint freeq.example:51820 \
    --gateway-peer-env https://freeq.example:8792/v1/public-peer.env \
    --remote-overlay 10.66.0.2/32 \
    --auto-start

Gateway publishes its public peer.env (run on gateway host):
  freeq pair publish --port 8792
  # Leaves fetch: http://GATEWAY_IP:8792/v1/public-peer.env

Fully automated bootstrap from environment (installers / cloud-init):
  FREEQ_GATEWAY_ENDPOINT=gw:51820 \
  FREEQ_GATEWAY_PEER_URL=http://gw:8792/v1/public-peer.env \
  FREEQ_REMOTE_OVERLAY=10.66.0.2/32 \
  freeq pair bootstrap --auto-start

  # Or direct:
  FREEQ_PAIR_URL=http://host:8791 FREEQ_PAIR_CODE=ABCD freeq pair bootstrap --auto-start

Private keys never leave the node. Prefer short-lived pair codes.
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

detect_lan_ip() {
  local ip=""
  if command -v ipconfig >/dev/null 2>&1; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1; exit}' || true)"
  fi
  printf '%s\n' "${ip:-THIS_HOST_IP}"
}

platform_start() {
  local config="${1:-$FREEQ_CONFIG}"
  local peer_env="${2:-}"
  case "$(uname -s)" in
    Darwin)
      if [ -x "$SCRIPT_DIR/freeq-start-macos.sh" ]; then
        if [ -n "$peer_env" ]; then
          FREEQ_PEER_ENV="$peer_env" "$SCRIPT_DIR/freeq-start-macos.sh" --restart --config "$config" --peer-env "$peer_env"
        else
          "$SCRIPT_DIR/freeq-start-macos.sh" --restart --config "$config"
        fi
        return 0
      fi
      if [ -x "$SCRIPT_DIR/freeq-connect-macos.sh" ] && [ -n "$peer_env" ]; then
        "$SCRIPT_DIR/freeq-connect-macos.sh" --restart --peer-env "$peer_env"
        return 0
      fi
      ;;
    Linux)
      if [ -x "$SCRIPT_DIR/freeq-start-linux.sh" ]; then
        FREEQ_CONFIG="$config" "$SCRIPT_DIR/freeq-start-linux.sh" --restart --config "$config"
        return 0
      fi
      ;;
  esac
  echo "No platform start helper found; config is ready at $config" >&2
  return 1
}

render_and_start_peer() {
  local peer_env="$1"
  local mode="${2:-direct}"
  local extra="${3:-}"
  freeq_ensure_dirs
  local out="${FREEQ_CONFIG:-$FREEQ_PERF_DIR/freeq.toml}"
  local args=(--peer-env "$peer_env" --output "$out" --mode "$mode")
  if [ -n "$extra" ]; then
    args+=(--extra-allowed-ips "$extra")
  fi
  "$SCRIPT_DIR/freeq-render-config.sh" "${args[@]}"
  platform_start "$out" "$peer_env"
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
    code="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
  fi
  local host_peer lan_ip
  host_peer="$(read_local_public_peer_env)"
  lan_ip="$(detect_lan_ip)"
  local guest_out="$FREEQ_PAIR_DIR/guest-peer.env"
  echo "FreeQ pair host listening on ${bind}:${port}"
  echo "  Pair code: $code"
  echo "  Detected LAN IP: $lan_ip"
  echo "  Waiting for one guest (Ctrl+C to cancel)..."
  echo ""
  echo "=== Other node (no .env files to copy) ==="
  echo "  freeq pair join-host --url http://${lan_ip}:${port} --code ${code} --auto-start"
  echo "========================================="

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
    render_and_start_peer "$installed" direct
  else
    echo "Next: freeq pair connect --peer-env $installed"
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
    render_and_start_peer "$installed" direct
  else
    echo "Next: freeq pair connect --peer-env $installed"
  fi
}

cmd_gateway() {
  freeq_ensure_dirs
  local gw_endpoint="" gw_peer="" gw_url="" remote_overlays="" auto_start=0
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
  # Env fallbacks for fully automated installers (no CLI flags required).
  gw_endpoint="${gw_endpoint:-${FREEQ_GATEWAY_ENDPOINT:-}}"
  gw_url="${gw_url:-${FREEQ_GATEWAY_PEER_URL:-}}"
  gw_peer="${gw_peer:-${FREEQ_GATEWAY_PEER_ENV:-}}"
  remote_overlays="${remote_overlays:-${FREEQ_REMOTE_OVERLAY:-${FREEQ_REMOTE_OVERLAYS:-}}}"

  if [ -z "$gw_endpoint" ]; then
    echo "--gateway-endpoint HOST:PORT is required (or FREEQ_GATEWAY_ENDPOINT)" >&2
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
    echo "need --gateway-peer-env PATH|URL or --gateway-peer-url URL (or FREEQ_GATEWAY_PEER_URL)" >&2
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
  gw_name="${gw_name:-gateway}"
  local installed
  installed="$(install_peer_env_content "$gw_name" "$content")"
  echo "Installed gateway peer: $installed"
  echo "  endpoint: $gw_endpoint"
  echo "  remote overlays: ${remote_overlays:-none}"

  if [ "$auto_start" -eq 1 ]; then
    if [ -z "$remote_overlays" ]; then
      echo "WARN: no --remote-overlay; leaf can reach gateway but not remote /32 peers yet." >&2
    fi
    render_and_start_peer "$installed" gateway_client "$remote_overlays"
  else
    echo "Next (zero file trade):"
    echo "  freeq pair gateway --gateway-endpoint $gw_endpoint \\"
    echo "    --gateway-peer-env $installed --remote-overlay OTHER/32 --auto-start"
  fi
}

# Publish this node's PUBLIC peer.env for leaves (gateway or hub).
# Never serves private keys / node.env / identity.key.
cmd_publish() {
  need python3
  freeq_ensure_dirs
  local port=8792 bind="0.0.0.0" code=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --port) port="$2"; shift 2 ;;
      --bind) bind="$2"; shift 2 ;;
      --code) code="$2"; shift 2 ;;
      --help|-h)
        echo "Usage: freeq pair publish [--port 8792] [--code OPTIONAL_BEARER]"
        exit 0
        ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  local peer
  peer="$(read_local_public_peer_env)"
  # Refuse if content looks like a private identity
  if printf '%s\n' "$peer" | grep -qiE 'PRIVATE|identity\.key|SECRET_KEY'; then
    echo "Refusing to publish peer material that looks private." >&2
    exit 1
  fi
  local lan_ip
  lan_ip="$(detect_lan_ip)"
  echo "Publishing PUBLIC peer.env only (no private keys)"
  echo "  Listen: ${bind}:${port}"
  echo "  Fetch:  http://${lan_ip}:${port}/v1/public-peer.env"
  if [ -n "$code" ]; then
    echo "  Auth:   Bearer $code"
  else
    echo "  Auth:   open on this port (bind to LAN/VPN only in production)"
  fi
  FREEQ_PUBLISH_PEER="$peer" \
  FREEQ_PUBLISH_CODE="$code" \
  FREEQ_PUBLISH_BIND="$bind" \
  FREEQ_PUBLISH_PORT="$port" \
  python3 <<'PY'
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PEER = os.environ["FREEQ_PUBLISH_PEER"].encode()
if not PEER.endswith(b"\n"):
    PEER += b"\n"
CODE = os.environ.get("FREEQ_PUBLISH_CODE") or ""
BIND = os.environ.get("FREEQ_PUBLISH_BIND", "0.0.0.0")
PORT = int(os.environ.get("FREEQ_PUBLISH_PORT", "8792"))

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return
    def _auth(self):
        if not CODE:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {CODE}" or self.headers.get("X-FreeQ-Pair-Code") == CODE
    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        if path not in ("/v1/public-peer.env", "/v1/pair/public-peer", "/peer.env"):
            self.send_error(404)
            return
        if not self._auth():
            self.send_error(401)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-FreeQ-Material", "public-peer-only")
        self.end_headers()
        self.wfile.write(PEER)

print(f"publish server on {BIND}:{PORT}", flush=True)
HTTPServer((BIND, PORT), H).serve_forever()
PY
}

# Env-driven auto pair for installers (no human CLI args).
cmd_bootstrap() {
  local auto_start=1
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --auto-start) auto_start=1; shift ;;
      --no-start) auto_start=0; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  # Prefer gateway leaf automation when gateway vars present.
  if [ -n "${FREEQ_GATEWAY_ENDPOINT:-}" ] && {
       [ -n "${FREEQ_GATEWAY_PEER_URL:-}" ] || [ -n "${FREEQ_GATEWAY_PEER_ENV:-}" ]
     }; then
    local args=(--gateway-endpoint "$FREEQ_GATEWAY_ENDPOINT")
    if [ -n "${FREEQ_GATEWAY_PEER_URL:-}" ]; then
      args+=(--gateway-peer-url "$FREEQ_GATEWAY_PEER_URL")
    else
      args+=(--gateway-peer-env "$FREEQ_GATEWAY_PEER_ENV")
    fi
    if [ -n "${FREEQ_REMOTE_OVERLAY:-}" ]; then
      # support comma-separated list
      local o
      IFS=',' read -ra _ovs <<<"$FREEQ_REMOTE_OVERLAY"
      for o in "${_ovs[@]}"; do
        o="$(echo "$o" | tr -d ' ')"
        [ -n "$o" ] && args+=(--remote-overlay "$o")
      done
    fi
    [ "$auto_start" -eq 1 ] && args+=(--auto-start)
    echo "bootstrap: gateway leaf (zero .env file trade)"
    cmd_gateway "${args[@]}"
    return 0
  fi
  if [ -n "${FREEQ_PAIR_URL:-}" ] && [ -n "${FREEQ_PAIR_CODE:-}" ]; then
    local args=(--url "$FREEQ_PAIR_URL" --code "$FREEQ_PAIR_CODE")
    [ "$auto_start" -eq 1 ] && args+=(--auto-start)
    echo "bootstrap: join-host (zero .env file trade)"
    cmd_join_host "${args[@]}"
    return 0
  fi
  echo "bootstrap: nothing to do — set either:" >&2
  echo "  FREEQ_GATEWAY_ENDPOINT + FREEQ_GATEWAY_PEER_URL [+ FREEQ_REMOTE_OVERLAY]" >&2
  echo "  or FREEQ_PAIR_URL + FREEQ_PAIR_CODE" >&2
  exit 2
}

cmd_connect() {
  local peer_env="" mode="direct" extra=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --peer-env) peer_env="$2"; shift 2 ;;
      --mode) mode="$2"; shift 2 ;;
      --extra-allowed-ips) extra="$2"; shift 2 ;;
      *) echo "unknown: $1" >&2; exit 1 ;;
    esac
  done
  if [ -z "$peer_env" ]; then
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
  render_and_start_peer "$peer_env" "$mode" "$extra"
}

case "$CMD" in
  show|"") cmd_show "$@" ;;
  invite) cmd_invite "$@" ;;
  join) cmd_join "$@" ;;
  host) cmd_host "$@" ;;
  join-host) cmd_join_host "$@" ;;
  gateway) cmd_gateway "$@" ;;
  publish) cmd_publish "$@" ;;
  bootstrap|auto) cmd_bootstrap "$@" ;;
  connect) cmd_connect "$@" ;;
  help|-h|--help) usage ;;
  *) echo "Unknown command: $CMD" >&2; usage >&2; exit 1 ;;
esac
