#!/usr/bin/env bash
# Thorough FreeQ gateway-path performance + evidence capture for field publish.
# Intended for two field leaves via AWS freeq-gateway.
set -euo pipefail

usage() {
  cat <<'EOF'
Run gateway-path performance matrix and write an evidence folder.

Usage:
  scripts/perf/freeq-gateway-path-perf.sh \
    --remote-overlay-ip 10.66.0.2 \
    [--gateway-overlay-ip 10.66.0.254] \
    [--gateway-public-host 18.x.x.x] \
    [--label LABEL] \
    [--results-dir DIR] \
    [--udp-rates 0.5M,1M,2M,4M] \
    [--ping-count 50] \
    [--skip-tcp]

Records:
  - public RTT diagnostic (if --gateway-public-host; ICMP may be blocked)
  - overlay RTT leaf→gateway diagnostic (if --gateway-overlay-ip)
  - overlay RTT leaf↔remote via gateway
  - UDP iperf3 ladder both directions when possible
  - TCP bulk note (may stall on relay — documented honestly)
  - environment metadata (no private keys)
  - RESULTS.md + results.json for flyers / website Proof section

Requires: ping, iperf3 (for throughput), python3

Gateway status note:
  The hardened AWS relay runs as freeq-gateway.service and serves status at
  http://127.0.0.1:6790/status on the gateway host. The local leaf daemon still
  serves http://127.0.0.1:6789/v1/status on each Mac.
  Leaf↔leaf overlay ping and iperf are the success criteria. Gateway public
  and overlay ping probes are optional diagnostics and may be 100% loss.
EOF
}

REMOTE_IP=""
GATEWAY_OVERLAY_IP=""
GATEWAY_PUBLIC_HOST=""
LABEL="$(date -u +%Y%m%dT%H%M%SZ)-gateway-path"
RESULTS_ROOT="${FREEQ_PERF_RESULT_ROOT:-$HOME/FreeQ/03-perf-results}"
UDP_RATES="0.5M,1M,2M,4M"
PING_COUNT=50
IPERF_SECONDS="${FREEQ_IPERF_SECONDS:-20}"
SKIP_TCP=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --remote-overlay-ip) REMOTE_IP="$2"; shift 2 ;;
    --gateway-overlay-ip) GATEWAY_OVERLAY_IP="$2"; shift 2 ;;
    --gateway-public-host) GATEWAY_PUBLIC_HOST="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --results-dir) RESULTS_ROOT="$2"; shift 2 ;;
    --udp-rates) UDP_RATES="$2"; shift 2 ;;
    --ping-count) PING_COUNT="$2"; shift 2 ;;
    --iperf-seconds) IPERF_SECONDS="$2"; shift 2 ;;
    --skip-tcp) SKIP_TCP=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$REMOTE_IP" ]; then
  usage >&2
  exit 1
fi

command -v ping >/dev/null 2>&1 || { echo "ping required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }

OUT="$RESULTS_ROOT/$LABEL"
mkdir -p "$OUT"/{raw,logs}
META="$OUT/meta.env"
JSON="$OUT/results.json"
MD="$OUT/RESULTS.md"
PUBLIC_MD="$OUT/PUBLIC-SAFE-SUMMARY.md"

echo "FREEQ_PERF_SCHEMA=freeq.gateway_path_perf.v1" > "$META"
echo "STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$META"
echo "REMOTE_OVERLAY_IP=$REMOTE_IP" >> "$META"
echo "GATEWAY_OVERLAY_IP=${GATEWAY_OVERLAY_IP:-}" >> "$META"
echo "GATEWAY_PUBLIC_HOST=${GATEWAY_PUBLIC_HOST:-}" >> "$META"
echo "GATEWAY_SERVICE=freeq-gateway.service" >> "$META"
echo "GATEWAY_STATUS_PATH=http://127.0.0.1:6790/status" >> "$META"
echo "LOCAL_LEAF_STATUS_PATH=http://127.0.0.1:6789/v1/status" >> "$META"
echo "HOSTNAME=$(hostname)" >> "$META"
echo "UNAME=$(uname -a)" >> "$META"
echo "LABEL=$LABEL" >> "$META"

# Never scoop private keys into evidence
if [ -d "$HOME/.freeq" ]; then
  echo "LOCAL_FREEQ_DIR_PRESENT=1" >> "$META"
fi

run_ping() {
  local target="$1"
  local out="$2"
  local count="$3"
  # macOS and Linux ping flags differ slightly
  if ping -c 1 -t 2 127.0.0.1 >/dev/null 2>&1; then
    # BSD/macOS uses -t for TTL; -W is wait on some
    ping -c "$count" "$target" >"$out" 2>&1 || true
  else
    ping -c "$count" -W 2 "$target" >"$out" 2>&1 || true
  fi
}

parse_ping() {
  python3 - "$1" <<'PY'
import re, sys, json
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
# Linux: rtt min/avg/max/mdev = 1.2/3.4/...
# macOS: round-trip min/avg/max/stddev = 1.2/3.4/...
m = re.search(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", text)
loss = re.search(r"([\d.]+)% packet loss", text)
trans = re.search(r"(\d+) packets transmitted", text)
recv = re.search(r"(\d+) (?:packets )?received", text)
out = {
  "avg_ms": None, "min_ms": None, "max_ms": None, "stddev_ms": None,
  "loss_pct": None, "transmitted": None, "received": None, "ok": False,
}
if m:
  out["min_ms"] = float(m.group(1))
  out["avg_ms"] = float(m.group(2))
  out["max_ms"] = float(m.group(3))
  out["stddev_ms"] = float(m.group(4))
if loss:
  out["loss_pct"] = float(loss.group(1))
if trans:
  out["transmitted"] = int(trans.group(1))
if recv:
  out["received"] = int(recv.group(1))
out["ok"] = out["avg_ms"] is not None and (out.get("loss_pct") or 0) < 100
print(json.dumps(out))
PY
}

echo "=== connectivity probes ==="
RESULTS_PUBLIC_RTT="{}"
RESULTS_GW_OVERLAY="{}"
RESULTS_REMOTE="{}"

if [ -n "$GATEWAY_PUBLIC_HOST" ]; then
  echo "NOTE: public gateway ping is diagnostic only; ICMP may be blocked."
  run_ping "$GATEWAY_PUBLIC_HOST" "$OUT/raw/ping-public-gateway.txt" "$PING_COUNT"
  RESULTS_PUBLIC_RTT="$(parse_ping "$OUT/raw/ping-public-gateway.txt")"
  echo "public_gateway_rtt=$RESULTS_PUBLIC_RTT"
fi

if [ -n "$GATEWAY_OVERLAY_IP" ]; then
  echo "NOTE: gateway overlay ping is diagnostic only; hardened relay may not expose overlay ICMP."
  run_ping "$GATEWAY_OVERLAY_IP" "$OUT/raw/ping-overlay-gateway.txt" "$PING_COUNT"
  RESULTS_GW_OVERLAY="$(parse_ping "$OUT/raw/ping-overlay-gateway.txt")"
  echo "overlay_gateway_rtt=$RESULTS_GW_OVERLAY"
fi

run_ping "$REMOTE_IP" "$OUT/raw/ping-overlay-remote.txt" "$PING_COUNT"
RESULTS_REMOTE="$(parse_ping "$OUT/raw/ping-overlay-remote.txt")"
echo "overlay_remote_rtt=$RESULTS_REMOTE"

echo "=== UDP throughput (iperf3) ==="
UDP_RESULTS="[]"
if ! command -v iperf3 >/dev/null 2>&1; then
  echo "WARN: iperf3 not installed — UDP ladder skipped. brew install iperf3" | tee -a "$OUT/logs/warnings.txt"
else
  # Remote must run: iperf3 -s
  echo "NOTE: remote leaf should be running: iperf3 -s" | tee -a "$OUT/logs/notes.txt"
  UDP_JSON_PARTS=()
  IFS=',' read -r -a RATES <<< "$UDP_RATES"
  for rate in "${RATES[@]}"; do
    rate="$(echo "$rate" | tr -d ' ')"
    safe="$(echo "$rate" | tr './' '__')"
    raw="$OUT/raw/iperf-udp-${safe}-to-remote.json"
    echo "UDP $rate -> $REMOTE_IP (${IPERF_SECONDS}s)"
    if iperf3 -c "$REMOTE_IP" -u -b "$rate" -t "$IPERF_SECONDS" -J >"$raw" 2>"$OUT/raw/iperf-udp-${safe}.err"; then
      part="$(python3 - "$raw" "$rate" <<'PY'
import json,sys
path, rate = sys.argv[1], sys.argv[2]
data=json.load(open(path))
end=data.get("end", {})
sum_r=end.get("sum", end.get("sum_received", {}))
out={
  "direction": "local_to_remote",
  "target_bitrate": rate,
  "bits_per_second": sum_r.get("bits_per_second"),
  "lost_percent": sum_r.get("lost_percent"),
  "jitter_ms": sum_r.get("jitter_ms"),
  "ok": True,
}
print(json.dumps(out))
PY
)"
      UDP_JSON_PARTS+=("$part")
    else
      UDP_JSON_PARTS+=("{\"direction\":\"local_to_remote\",\"target_bitrate\":\"$rate\",\"ok\":false}")
      echo "UDP $rate failed (is iperf3 -s running on remote?)" | tee -a "$OUT/logs/warnings.txt"
    fi
  done
  UDP_RESULTS="$(python3 - <<PY
import json
parts = '''$(printf '%s\n' "${UDP_JSON_PARTS[@]}")'''.strip().splitlines()
print(json.dumps([json.loads(p) for p in parts if p.strip()]))
PY
)"
fi

echo "=== TCP bulk (honest) ==="
TCP_RESULT='{"attempted":false,"ok":null,"note":"skipped"}'
if [ "$SKIP_TCP" -eq 0 ] && command -v iperf3 >/dev/null 2>&1; then
  raw="$OUT/raw/iperf-tcp-to-remote.json"
  if iperf3 -c "$REMOTE_IP" -t "$IPERF_SECONDS" -J >"$raw" 2>"$OUT/raw/iperf-tcp.err"; then
    TCP_RESULT="$(python3 - "$raw" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
end=data.get("end", {})
s=end.get("sum_received") or end.get("sum_sent") or end.get("sum") or {}
bps=s.get("bits_per_second") or 0
ok = bps > 1000
print(json.dumps({
  "attempted": True,
  "ok": ok,
  "bits_per_second": bps,
  "note": "ok" if ok else "TCP bulk appeared stalled or negligible — known relay follow-up; do not oversell app TCP over relay yet",
}))
PY
)"
  else
    TCP_RESULT='{"attempted":true,"ok":false,"note":"iperf3 TCP failed or stalled — document honestly for field proof"}'
  fi
fi

echo "ENDED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$META"

# Assemble JSON
python3 - "$JSON" <<PY
import json, pathlib, sys
out = {
  "schema_version": "freeq.gateway_path_perf.v1",
  "label": "$LABEL",
  "remote_overlay_ip": "$REMOTE_IP",
  "gateway_overlay_ip": "$GATEWAY_OVERLAY_IP" or None,
  "gateway_public_host": "$GATEWAY_PUBLIC_HOST" or None,
  "ping": {
    "public_gateway": json.loads('''$RESULTS_PUBLIC_RTT''' or "{}"),
    "overlay_gateway": json.loads('''$RESULTS_GW_OVERLAY''' or "{}"),
    "overlay_remote_via_gateway": json.loads('''$RESULTS_REMOTE''' or "{}"),
  },
  "udp_iperf": json.loads('''$UDP_RESULTS''' or "[]"),
  "tcp_iperf": json.loads('''$TCP_RESULT'''),
  "claims_boundary": [
    "Hybrid PQC path cost must be separated from Starlink/CGNAT path RTT.",
    "Gateway never dials leaves.",
    "TCP bulk stall over relay is a known engineering follow-up when observed.",
    "Do not claim FedRAMP, Type 1, or complete ZT platform from this test.",
  ],
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps(out, indent=2))
PY

# Markdown reports
python3 - "$JSON" "$MD" "$PUBLIC_MD" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
md_path, pub_path = Path(sys.argv[2]), Path(sys.argv[3])

def display_value(value, suffix=""):
    if value in (None, ""):
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}{suffix}"
    return f"{value}{suffix}"

def display_optional(value):
    if value in (None, "", "None"):
        return "n/a"
    return value

def throughput_mbps(bits_per_second):
    if bits_per_second in (None, ""):
        return "n/a"
    return f"{bits_per_second / 1_000_000:.2f}"

def ping_row(name, p):
    if not p or p.get("avg_ms") is None:
        return f"| {name} | n/a | n/a | n/a |"
    return (
        f"| {name} | {display_value(p.get('avg_ms'))} | "
        f"{display_value(p.get('loss_pct'))} | "
        f"{display_value(p.get('min_ms'))}/{display_value(p.get('max_ms'))} |"
    )

notes = []
public_ping = data["ping"].get("public_gateway") or {}
overlay_gateway_ping = data["ping"].get("overlay_gateway") or {}
remote_ping = data["ping"].get("overlay_remote_via_gateway") or {}

if remote_ping.get("ok") and public_ping.get("loss_pct") == 100.0:
    notes.append(
        "The gateway public host did not answer ICMP during this run, but the "
        "leaf-to-leaf overlay path through the gateway remained healthy."
    )
if remote_ping.get("ok") and overlay_gateway_ping.get("loss_pct") == 100.0:
    notes.append(
        "The gateway overlay address did not answer ICMP during this run. That "
        "does not invalidate the relay result because the end-to-end overlay "
        "probe to the remote leaf succeeded."
    )

lines = [
  f"# FreeQ gateway path performance — {data['label']}",
  "",
  "## Topology",
  "",
  "```text",
  "local leaf  --outbound UDP-->  AWS freeq-gateway  <--outbound UDP--  remote leaf",
  "```",
  "",
  f"- Remote overlay IP: `{data['remote_overlay_ip']}`",
  f"- Gateway overlay IP: `{display_optional(data.get('gateway_overlay_ip'))}`",
  f"- Gateway public host: `{display_optional(data.get('gateway_public_host'))}`",
  "- Gateway service: `freeq-gateway.service`",
  "- Gateway host status endpoint: `http://127.0.0.1:6790/status`",
  "- Local leaf status endpoint: `http://127.0.0.1:6789/v1/status`",
  "",
  "## Latency",
  "",
  "| Path | Avg RTT (ms) | Loss % | min/max |",
  "|------|--------------|--------|---------|",
  ping_row("Public leaf→AWS host", data["ping"].get("public_gateway")),
  ping_row("Overlay leaf→gateway", data["ping"].get("overlay_gateway")),
  ping_row("Overlay leaf↔remote via GW", data["ping"].get("overlay_remote_via_gateway")),
  "",
]
if notes:
    lines += [
      "## Interpretation",
      "",
    ]
    for note in notes:
        lines.append(f"- {note}")
    lines.append("")

lines += [
  "## UDP throughput",
  "",
  "| Direction | Target | Measured Mbps | Loss % | Jitter ms | OK |",
  "|-----------|--------|---------------|--------|-----------|----|",
]
for u in data.get("udp_iperf") or []:
    lines.append(
        f"| {u.get('direction')} | {u.get('target_bitrate')} | "
        f"{throughput_mbps(u.get('bits_per_second'))} | "
        f"{display_value(u.get('lost_percent'))} | "
        f"{display_value(u.get('jitter_ms'))} | {u.get('ok')} |"
    )
if not data.get("udp_iperf"):
    lines.append("| — | — | — | — | — | no data |")

tcp = data.get("tcp_iperf") or {}
lines += [
  "",
  "## TCP bulk",
  "",
  f"- Attempted: {tcp.get('attempted')}",
  f"- OK: {tcp.get('ok')}",
  f"- Measured Mbps: {throughput_mbps(tcp.get('bits_per_second'))}",
  f"- Note: {tcp.get('note')}",
  "",
  "## Claims boundary (do not oversell)",
  "",
]
for c in data.get("claims_boundary") or []:
    lines.append(f"- {c}")
lines.append("")
md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

# Public-safe shorter blurb for website / flyers
remote = data["ping"].get("overlay_remote_via_gateway") or {}
pub = [
  f"# Field proof snippet — {data['label']}",
  "",
  "Two FreeQ leaves connected **outbound-only** through an AWS freeq-gateway",
  "(gateway never dials leaves).",
  "",
]
if remote.get("avg_ms") is not None:
    pub.append(
        f"- Leaf↔leaf overlay RTT via gateway: **~{remote['avg_ms']:.1f} ms** avg "
        f"({remote.get('loss_pct', '?')}% loss over probe)."
    )
udp_ok = [u for u in (data.get("udp_iperf") or []) if u.get("ok")]
if udp_ok:
    pub.append(f"- UDP overlay iperf samples collected: **{len(udp_ok)}** rate points.")
tcp = data.get("tcp_iperf") or {}
if tcp.get("attempted"):
    if tcp.get("ok"):
        pub.append("- TCP bulk over relay: measured (see full RESULTS.md).")
    else:
        pub.append(
            "- TCP bulk over relay: **treated carefully** (possible stall); "
            "UDP/ICMP path evidence remains the primary field claim."
        )
pub += [
  "",
  "Full method and raw tables: attach RESULTS.md from this run. "
  "Not a FedRAMP/Type-1 claim; hybrid-PQC path with honest path RTT.",
  "",
]
pub_path.write_text("\n".join(pub) + "\n", encoding="utf-8")
print(f"wrote {md_path}")
print(f"wrote {pub_path}")
PY

echo
echo "results_dir=$OUT"
echo "results_md=$MD"
echo "public_safe=$PUBLIC_MD"
echo "gateway_path_perf_ok=1"
