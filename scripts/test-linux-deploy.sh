#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== linux deploy: static role contract =="

python3 - <<'PY'
from pathlib import Path

root = Path.cwd()

def read(path: str) -> str:
    return (root / path).read_text()

def require(path: str, needle: str) -> None:
    text = read(path)
    if needle not in text:
        raise SystemExit(f"{path} is missing required text: {needle}")

def forbid(path: str, needle: str) -> None:
    text = read(path)
    if needle in text:
        raise SystemExit(f"{path} contains forbidden text: {needle}")

defaults = "deploy/ansible/roles/freeqd/defaults/main.yml"
tasks = "deploy/ansible/roles/freeqd/tasks/main.yml"
config_template = "deploy/ansible/roles/freeqd/templates/freeq.toml.j2"
unit_template = "deploy/ansible/roles/freeqd/templates/freeqd.service.j2"

require(defaults, 'freeq_api_addr: "127.0.0.1:6789"')
require(defaults, "freeq_allow_unsafe_api_bind: false")
require(defaults, "freeq_strict_cloaking: false")

require(config_template, "allow_unsafe_api_bind = {{ freeq_allow_unsafe_api_bind")
require(config_template, "strict_cloaking = {{ freeq_strict_cloaking")

require(tasks, "freeq_allow_unsafe_api_bind | bool")
require(tasks, "freeq_api_addr is match")
require(tasks, "loopback freeq_api_addr")

for directive in [
    "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
    "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "PrivateMounts=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "ProtectClock=true",
    "ProtectHostname=true",
    "ProtectKernelTunables=true",
    "ProtectKernelModules=true",
    "ProtectKernelLogs=true",
    "ProtectControlGroups=true",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
    "RestrictRealtime=true",
    "RestrictSUIDSGID=true",
    "LockPersonality=true",
    "MemoryDenyWriteExecute=true",
    "SystemCallArchitectures=native",
    "DeviceAllow=/dev/net/tun rw",
]:
    require(unit_template, directive)

for forbidden in [
    "CapabilityBoundingSet=~",
    "AmbientCapabilities=CAP_SYS_ADMIN",
    "ReadWritePaths=/",
    "ProtectSystem=false",
    "NoNewPrivileges=false",
]:
    forbid(unit_template, forbidden)

print("linux role static contract checks passed")
PY

if command -v ansible-playbook >/dev/null 2>&1; then
  echo "== linux deploy: ansible syntax =="
  (
    cd deploy/ansible
    ansible-playbook playbooks/site.yml --syntax-check
  )
else
  echo "== linux deploy: ansible syntax skipped; ansible-playbook not installed =="
fi

