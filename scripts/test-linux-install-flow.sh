#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/scripts/install/freeq-install-linux.sh"
HARNESS="$ROOT/scripts/test-linux-install-flow.sh"
FIXTURES="$ROOT/scripts/fixtures/linux-os-release"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/freeq-linux-install.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "FAIL: $file does not contain: $needle" >&2
    exit 1
  fi
}

echo "== linux install: shell syntax =="
bash -n "$INSTALLER" "$HARNESS"

echo "== linux install: static command guardrails =="
python3 - "$INSTALLER" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
patterns = {
    "sudo invocation": r"(^|[;&|()\s])sudo\s+",
    "systemctl invocation": r"(^|[;&|()\s])systemctl\s+",
    "ip route mutation": r"(^|[;&|()\s])ip\s+route\s+",
    "NetworkManager mutation": r"(^|[;&|()\s])nmcli\s+(connection|device|general|networking)",
    "netplan mutation": r"(^|[;&|()\s])netplan\s+apply\s*$",
    "module mutation": r"(^|[;&|()\s])modprobe\s+",
    "capability mutation": r"(^|[;&|()\s])setcap\s+",
    "package mutation": r"(^|[;&|()\s])(apt(-get)?|dnf|yum|pacman|apk|brew)\s+(install|update|upgrade|remove)\s+",
}
for label, pattern in patterns.items():
    if re.search(pattern, text, flags=re.MULTILINE):
        raise SystemExit(f"{label} found in installer")
print("static command guardrails passed")
PY

echo "== linux install: fixture-driven distro inspection =="
FAKE_BIN="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN"
printf '%s\n' '#!/usr/bin/env bash' 'printf "Linux\\n"' > "$FAKE_BIN/uname"
chmod +x "$FAKE_BIN/uname"

for command_name in cargo rustc ip systemctl brew apt-get dnf yum pacman apk sudo nmcli netplan modprobe setcap; do
  printf '%s\n' '#!/usr/bin/env bash' 'printf "unexpected command execution: %s\\n" "$0" >&2' 'exit 91' > "$FAKE_BIN/$command_name"
  chmod +x "$FAKE_BIN/$command_name"
done

export PATH="$FAKE_BIN:/usr/bin:/bin"
export FREEQ_LINUX_TUN_PATH="$TMP_DIR/missing-tun"

run_fixture() {
  local fixture="$1"
  local expected_id="$2"
  local expected_family="$3"
  local output="$TMP_DIR/${fixture}.out"
  FREEQ_LINUX_OS_RELEASE="$FIXTURES/$fixture.os-release" bash "$INSTALLER" > "$output"
  assert_contains "$output" "Mode: read-only inspection"
  assert_contains "$output" "Linux install status: planned/stubbed (not supported)"
  assert_contains "$output" "Distribution ID: $expected_id"
  assert_contains "$output" "Distribution family: $expected_family"
  assert_contains "$output" "No packages were installed. No services were changed. No host networking was changed."
}

run_fixture ubuntu ubuntu debian
run_fixture fedora fedora rhel
run_fixture alpine alpine alpine
run_fixture arch arch arch
run_fixture unknown unknown unknown

echo "== linux install: fixture inventory guardrail =="
for fixture in ubuntu fedora alpine arch unknown; do
  test -f "$FIXTURES/$fixture.os-release"
done

echo "== linux install: apply refusal =="
if bash "$INSTALLER" --apply > "$TMP_DIR/apply.out" 2>&1; then
  echo "FAIL: --apply unexpectedly succeeded" >&2
  exit 1
fi
assert_contains "$TMP_DIR/apply.out" "not implemented pending main-engineer review"
assert_contains "$TMP_DIR/apply.out" "No changes were made"

echo "linux install flow checks passed"
