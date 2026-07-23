#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_file_contains() {
  local file="$1"
  local pattern="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$file" || fail "expected $file to contain: $pattern"
  else
    grep -Eq "$pattern" "$file" || fail "expected $file to contain: $pattern"
  fi
}

assert_no_match() {
  local pattern="$1"
  shift
  if command -v rg >/dev/null 2>&1; then
    if rg -n "$pattern" "$@" >/tmp/freeq-setup-flow-search.out 2>/dev/null; then
      cat /tmp/freeq-setup-flow-search.out >&2
      fail "unexpected match for: $pattern"
    fi
  elif grep -ERn "$pattern" "$@" >/tmp/freeq-setup-flow-search.out 2>/dev/null; then
    cat /tmp/freeq-setup-flow-search.out >&2
    fail "unexpected match for: $pattern"
  fi
}

make_fake_command() {
  local path="$1"
  local body="$2"
  printf '%s\n' '#!/usr/bin/env bash' "$body" > "$path"
  chmod +x "$path"
}

TMP_ROOT="$(mktemp -d -t freeq-setup-flow.XXXXXX)"
trap 'rm -rf "$TMP_ROOT" /tmp/freeq-setup-flow-search.out' EXIT

echo "== setup flow: dry run =="
DRY_HOME="$TMP_ROOT/dry-home"
mkdir -p "$DRY_HOME"
FREEQ_ASSUME_DEFAULTS=1 \
FREEQ_NODE_NAME=lap21 \
FREEQ_OVERLAY_ADDRESS=10.66.0.44/24 \
FREEQ_PUBLIC_ENDPOINT=lap21.example.test:51820 \
HOME="$DRY_HOME" \
scripts/setup/freeq-setup-macos.sh --dry-run > "$TMP_ROOT/dry-run.out"
assert_file_contains "$TMP_ROOT/dry-run.out" "Dry run only"
assert_file_contains "$TMP_ROOT/dry-run.out" "Node name: lap21"
assert_file_contains "$TMP_ROOT/dry-run.out" "Public endpoint to share: lap21.example.test:51820"
[ ! -e "$DRY_HOME/FreeQ" ] || fail "dry run created visible setup folder"
[ ! -e "$DRY_HOME/.freeq" ] || fail "dry run created hidden internal folder"

echo "== setup flow: invalid listen address resets before config =="
BAD_LISTEN_HOME="$TMP_ROOT/bad-listen-home"
mkdir -p "$BAD_LISTEN_HOME"
FREEQ_ASSUME_DEFAULTS=1 \
FREEQ_NODE_NAME=bad-listen \
FREEQ_LISTEN_ADDR=192.168.1.1.140:51820 \
HOME="$BAD_LISTEN_HOME" \
scripts/setup/freeq-setup-macos.sh --dry-run > "$TMP_ROOT/bad-listen.out"
assert_file_contains "$TMP_ROOT/bad-listen.out" "Invalid local listen address"
assert_file_contains "$TMP_ROOT/bad-listen.out" "Listen address: 0.0.0.0:51820"

echo "== setup flow: simple installer syntax and dry run =="
bash -n scripts/install/freeq-install-macos.sh
FREEQ_INSTALL_DIR="$TMP_ROOT/simple-install/freeq-core" \
FREEQ_SETUP_DIR="$TMP_ROOT/simple-install/FreeQ" \
scripts/install/freeq-install-macos.sh --dry-run > "$TMP_ROOT/simple-install.out"
assert_file_contains "$TMP_ROOT/simple-install.out" "FreeQ macOS installer"
assert_file_contains "$TMP_ROOT/simple-install.out" "Dry run only"
assert_file_contains "$TMP_ROOT/simple-install.out" "Local setup page:"
assert_file_contains docs/simple-install.md "brew install freeq"
assert_file_contains docs/simple-install.md "Start, Connect, Roll Back"
assert_file_contains docs/simple-install.md "FreeQ rollback result: PASS"
assert_file_contains docs/simple-install.md "brew install freeq"
assert_file_contains docs/simple-install.md "brew upgrade freeq"
assert_file_contains docs/simple-install.md "freeq gateway"
assert_file_contains docs/simple-install.md "freeq stop"
assert_file_contains docs/setup-macos.md "Connect Through A Gateway When Needed"
assert_file_contains docs/setup-macos.md "Roll Back To Normal Networking"
assert_file_contains docs/setup-macos.md "brew install freeq"
assert_file_contains docs/setup-macos.md "brew upgrade freeq"
assert_file_contains docs/setup-macos.md "freeq gateway"
assert_file_contains docs/setup-macos.md "freeq stop"
assert_file_contains docs/perf-macos-quickstart.md "Gateway Or Relay Path"
assert_file_contains docs/perf-macos-quickstart.md "Roll Back And Resume Normal Networking"
assert_file_contains docs/perf-macos-quickstart.md "brew install freeq"
assert_file_contains docs/perf-macos-quickstart.md "freeq gateway"
assert_file_contains docs/perf-macos-quickstart.md "freeq stop"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "brew install freeq"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "freeq-io/tap/freeq"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "Homebrew core"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "macOS and Linux"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "supported Linux target"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "FreeQ Core owns"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "FreeQ Cloud"
assert_file_contains docs/homebrew-install-maintenance-strategy.md "Shell installer"
assert_file_contains docs/platform-installation-framework.md "Platform Matrix"
assert_file_contains docs/platform-installation-framework.md "Linux gateway/server"
assert_file_contains docs/platform-installation-framework.md "Windows workstation"
assert_file_contains docs/platform-installation-framework.md "winget install FreeQ.FreeQ"
assert_file_contains docs/platform-installation-framework.md "freeq service install"
assert_file_contains docs/platform-installation-framework.md "Platform Stub Template"
assert_file_contains docs/assets/index-DmLsYzhZ.js "Install FreeQ Now"
assert_file_contains docs/assets/index-DmLsYzhZ.js "Public alpha install"
assert_file_contains docs/assets/index-DmLsYzhZ.js "freeq-install-macos.sh"
assert_file_contains docs/assets/index-BbB4FHI-.css "section--install"
assert_file_contains dashboard/index.html "/v1/status"
assert_file_contains dashboard/index.html "/v1/peers"
assert_file_contains dashboard/index.html "/v1/invites"
assert_file_contains dashboard/index.html "/v1/invites/join"
assert_file_contains dashboard/index.html "Create 15-Minute Invite"
assert_file_contains dashboard/index.html "Send the code separately"
assert_file_contains dashboard/index.html "The tunnel counter stays at 0 until overlay traffic flows"
assert_file_contains dashboard/index.html "scripts/setup/freeq-connect-macos.sh --restart"
assert_file_contains crates/freeq-api/src/router.rs 'route\("/", get\(dashboard\)\)'
assert_file_contains crates/freeq-api/src/router.rs "/v1/invites"

echo "== setup flow: build identity helper =="
cargo build --release -p freeq-perf-identity >/dev/null

echo "== setup flow: peer file validates and renders =="
mkdir -p "$TMP_ROOT/local" "$TMP_ROOT/peer" "$TMP_ROOT/setup/02-put-peer-file-here"
target/release/freeq-perf-identity \
  --node-name local-mac \
  --overlay-address 10.66.0.20/24 \
  --listen 0.0.0.0:51820 \
  --public-endpoint local.example.test:51820 \
  --output-dir "$TMP_ROOT/local" >/dev/null
target/release/freeq-perf-identity \
  --node-name peer-mac \
  --overlay-address 10.66.0.21/24 \
  --listen 0.0.0.0:51820 \
  --public-endpoint peer.example.test:51820 \
  --output-dir "$TMP_ROOT/peer" >/dev/null
cp "$TMP_ROOT/peer/peer.env" "$TMP_ROOT/setup/02-put-peer-file-here/peer-mac-peer.env"
cp "$TMP_ROOT/local/peer.env" "$TMP_ROOT/setup/02-put-peer-file-here/local-mac-peer.env"
scripts/setup/freeq-validate-peer-env.sh "$TMP_ROOT/setup/02-put-peer-file-here/peer-mac-peer.env" > "$TMP_ROOT/validate.out"
assert_file_contains "$TMP_ROOT/validate.out" "Peer env is valid"
FREEQ_SETUP_DIR="$TMP_ROOT/setup" \
FREEQ_LOCAL_ENV="$TMP_ROOT/local/node.env" \
FREEQ_CONFIG_OUT="$TMP_ROOT/freeq.toml" \
scripts/setup/freeq-render-config.sh > "$TMP_ROOT/render.out" 2> "$TMP_ROOT/render.err"
assert_file_contains "$TMP_ROOT/render.err" "Ignoring local node peer file"
assert_file_contains "$TMP_ROOT/freeq.toml" 'name = "peer-mac"'
assert_file_contains "$TMP_ROOT/freeq.toml" 'endpoint = "peer.example.test:51820"'
rm -f "$TMP_ROOT/setup/02-put-peer-file-here/local-mac-peer.env"

echo "== setup flow: listen-only config renders without peer file =="
FREEQ_LOCAL_ENV="$TMP_ROOT/local/node.env" \
FREEQ_CONFIG_OUT="$TMP_ROOT/listen-only.toml" \
scripts/setup/freeq-render-config.sh --listen-only > "$TMP_ROOT/listen-only-render.out"
assert_file_contains "$TMP_ROOT/listen-only.toml" 'name = "local-mac"'
assert_file_contains "$TMP_ROOT/listen-only.toml" 'listen = "0.0.0.0:51820"'
assert_no_match '^\[\[peer\]\]' "$TMP_ROOT/listen-only.toml"
assert_file_contains "$TMP_ROOT/listen-only-render.out" "Rendered listen-only FreeQ config"

echo "== setup flow: bad local listen fails before daemon start =="
BAD_LOCAL_ENV="$TMP_ROOT/bad-local/node.env"
mkdir -p "$(dirname "$BAD_LOCAL_ENV")"
sed 's/FREEQ_NODE_LISTEN=.*/FREEQ_NODE_LISTEN='"'"'192.168.1.1.140:51820'"'"'/' "$TMP_ROOT/local/node.env" > "$BAD_LOCAL_ENV"
if FREEQ_LOCAL_ENV="$BAD_LOCAL_ENV" \
  FREEQ_CONFIG_OUT="$TMP_ROOT/bad-listen.toml" \
  scripts/setup/freeq-render-config.sh --listen-only > "$TMP_ROOT/bad-listen-render.out" 2> "$TMP_ROOT/bad-listen-render.err"; then
  fail "render accepted invalid FREEQ_NODE_LISTEN"
fi
assert_file_contains "$TMP_ROOT/bad-listen-render.err" "Invalid local listen address"

echo "== setup flow: incomplete peer file fails clearly =="
mkdir -p "$TMP_ROOT/bad-peer" "$TMP_ROOT/bad-setup/02-put-peer-file-here"
target/release/freeq-perf-identity \
  --node-name bad-peer \
  --overlay-address 10.66.0.22/24 \
  --listen 0.0.0.0:51820 \
  --public-endpoint '' \
  --output-dir "$TMP_ROOT/bad-peer" >/dev/null
cp "$TMP_ROOT/bad-peer/peer.env" "$TMP_ROOT/bad-setup/02-put-peer-file-here/bad-peer.env"
if scripts/setup/freeq-validate-peer-env.sh "$TMP_ROOT/bad-setup/02-put-peer-file-here/bad-peer.env" > "$TMP_ROOT/bad-validate.out" 2> "$TMP_ROOT/bad-validate.err"; then
  fail "validator accepted blank FREEQ_PUBLIC_ENDPOINT"
fi
assert_file_contains "$TMP_ROOT/bad-validate.err" "FREEQ_PUBLIC_ENDPOINT is missing or blank"
if FREEQ_SETUP_DIR="$TMP_ROOT/bad-setup" \
  FREEQ_LOCAL_ENV="$TMP_ROOT/local/node.env" \
  FREEQ_CONFIG_OUT="$TMP_ROOT/bad-freeq.toml" \
  scripts/setup/freeq-render-config.sh > "$TMP_ROOT/bad-render.out" 2> "$TMP_ROOT/bad-render.err"; then
  fail "render accepted blank FREEQ_PUBLIC_ENDPOINT"
fi
assert_file_contains "$TMP_ROOT/bad-render.err" "FREEQ_PUBLIC_ENDPOINT"

echo "== setup flow: direct perf infers target from peer file =="
FAKE_BIN="$TMP_ROOT/fake-bin"
mkdir -p "$FAKE_BIN" "$TMP_ROOT/results"
make_fake_command "$FAKE_BIN/ping" "exit 0"
make_fake_command "$FAKE_BIN/ssh" "exit 0"
make_fake_command "$FAKE_BIN/scp" "exit 0"
make_fake_command "$FAKE_BIN/iperf3" "echo '{}'"
FREEQ_SETUP_DIR="$TMP_ROOT/setup" \
FREEQ_PERF_RESULT_ROOT="$TMP_ROOT/results" \
FREEQ_SCP_MB=1 \
PATH="$FAKE_BIN:$PATH" \
scripts/perf/freeq-perf-run.sh --mode direct --label direct-test > "$TMP_ROOT/perf.out"
assert_file_contains "$TMP_ROOT/results/direct-test/run.env" "target_host=peer.example.test"

echo "== setup flow: macOS stop consumes rollback ledger =="
STOP_FAKE_BIN="$TMP_ROOT/stop-fake-bin"
mkdir -p "$STOP_FAKE_BIN"
cat > "$STOP_FAKE_BIN/sudo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$TMP_ROOT/stop-sudo.log"
exit 0
EOF
chmod +x "$STOP_FAKE_BIN/sudo"
cat > "$TMP_ROOT/freeq-network-state.env" <<'EOF'
FREEQ_STATE_VERSION='1'
FREEQ_PID_FILE='/tmp/freeq-test-missing.pid'
FREEQ_LOCAL_IP='10.66.0.20'
FREEQ_PEER_IP='10.66.0.21'
FREEQ_WIFI_SERVICE='Wi-Fi'
FREEQ_WIFI_DEVICE='en0'
FREEQ_WIFI_CONFIG_MODE='DHCP Configuration'
FREEQ_ADDED_LOCAL_ROUTE='1'
FREEQ_ADDED_PEER_ROUTE='1'
EOF
PATH="$STOP_FAKE_BIN:$PATH" \
  scripts/setup/freeq-stop-macos.sh --state-file "$TMP_ROOT/freeq-network-state.env" --renew-dhcp > "$TMP_ROOT/stop.out"
assert_file_contains "$TMP_ROOT/stop.out" "FreeQ macOS tunnel cleanup complete"
assert_file_contains "$TMP_ROOT/stop-sudo.log" "route -n delete -host 10.66.0.20"
assert_file_contains "$TMP_ROOT/stop-sudo.log" "route -n delete -host 10.66.0.21"
assert_file_contains "$TMP_ROOT/stop-sudo.log" "networksetup -setdhcp Wi-Fi"
assert_file_contains "$TMP_ROOT/stop-sudo.log" "ipconfig set en0 DHCP"
[ "$(grep -Ec '^-v$' "$TMP_ROOT/stop-sudo.log")" -eq 4 ] || fail "stop helper did not check sudo access for each privileged command"
[ ! -e "$TMP_ROOT/freeq-network-state.env" ] || fail "stop helper did not remove rollback ledger"

echo "== setup flow: guardrails =="
assert_no_match "FREEQ_PEER_ENDPOINT|PEER_ENDPOINT|--peer-endpoint" \
  scripts/setup scripts/perf docs/perf-macos-quickstart.md docs/perf-harness.md tools/freeq-perf-identity/src/main.rs
assert_no_match "patrick|david|Patrick|David" \
  scripts/setup scripts/perf docs/perf-macos-quickstart.md docs/perf-harness.md tools/freeq-perf-identity/src/main.rs
assert_no_match "~/.freeq|cd .*\\.freeq|open .*\\.freeq" docs/perf-macos-quickstart.md docs/perf-harness.md
assert_no_match "localStorage|sessionStorage|document.cookie|https://|http://[^1]" dashboard/index.html
assert_file_contains scripts/setup/freeq-setup-macos.sh "xcode-select --install"
assert_file_contains scripts/setup/freeq-setup-macos.sh "sh.rustup.rs"
assert_file_contains scripts/setup/freeq-setup-macos.sh "brew install iperf3 jq"
assert_file_contains scripts/setup/freeq-setup-macos.sh "FREEQ_PUBLIC_ENDPOINT=.*quote_shell"
assert_file_contains scripts/setup/freeq-setup-macos.sh "FREEQ_PEER_SSH_USER=.*quote_shell"
assert_file_contains scripts/setup/freeq-setup-macos.sh "freeq-stop-macos.sh --renew-dhcp"
assert_file_contains scripts/install/freeq-install-macos.sh "http://127.0.0.1:6789/"
assert_file_contains scripts/install/freeq-install-macos.sh "rollback"
assert_file_contains scripts/install/freeq-install-macos.sh "FreeQ update status:"
assert_file_contains scripts/install/freeq-install-macos.sh "FreeQ rollback result: PASS"
assert_file_contains scripts/install/freeq-install-macos.sh "scripts/setup/freeq-stop-macos.sh --renew-dhcp"
assert_file_contains scripts/install/freeq-install-macos.sh "freeq stop"
assert_file_contains Formula/freeq.rb "brew upgrade freeq"
assert_file_contains Formula/freeq.rb "freeq setup"
assert_file_contains Formula/freeq.rb "freeq gateway"
assert_file_contains Formula/freeq.rb "freeq stop"
assert_no_match "freeq --install|freeq --update|freeq --gateway|freeq --stop" cli/src/main.rs Formula/freeq.rb docs/simple-install.md docs/setup-macos.md docs/perf-macos-quickstart.md
assert_file_contains scripts/setup/freeq-start-macos.sh "Setup page:"
assert_file_contains scripts/setup/freeq-start-macos.sh "nohup sudo target/release/freeqd"
assert_file_contains scripts/setup/freeq-start-macos.sh "freeqd did not keep the local setup API online"
assert_file_contains scripts/setup/freeq-start-macos.sh "FREEQ_TUN_MTU"
assert_file_contains scripts/setup/freeq-start-macos.sh "freeq-network-state.env"
assert_file_contains scripts/setup/freeq-start-macos.sh "require_no_preexisting_overlay_route"
assert_file_contains scripts/setup/freeq-start-macos.sh "rollback_on_start_error"
assert_file_contains scripts/setup/freeq-start-macos.sh 'ifconfig "\$interface" mtu "\$TUN_MTU"'
assert_file_contains scripts/setup/freeq-start-macos.sh 'route -n add -host "\$local_ip" 127.0.0.1'
assert_file_contains scripts/setup/freeq-start-macos.sh 'route -n add -host "\$peer_ip" -interface "\$interface"'
assert_no_match 'route -n change -host "\$local_ip"|route -n change -host "\$peer_ip"' scripts/setup/freeq-start-macos.sh
assert_file_contains scripts/setup/freeq-start-macos.sh "freeq-stop-macos.sh --renew-dhcp"
assert_file_contains scripts/setup/freeq-stop-macos.sh "FREEQ_ADDED_LOCAL_ROUTE"
assert_file_contains scripts/setup/freeq-stop-macos.sh "FREEQ_ADDED_PEER_ROUTE"
assert_file_contains scripts/setup/freeq-stop-macos.sh 'route -n delete -host "\$ip"'
assert_file_contains scripts/setup/freeq-stop-macos.sh 'networksetup -setdhcp "\$WIFI_SERVICE"'
assert_file_contains scripts/setup/freeq-stop-macos.sh 'ipconfig set "\$WIFI_DEVICE" DHCP'
assert_file_contains scripts/setup/freeq-connect-macos.sh "Building updated freeqd release binary"
assert_file_contains scripts/setup/freeq-start-macos.sh "Building updated freeqd release binary"

echo "setup flow checks passed"
