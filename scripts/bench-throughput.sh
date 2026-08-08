#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: Root/sudo privileges required to configure kernel TUN interface drivers." >&2
    exit 1
fi

TUN_INTERFACE="freeqtun0"
TEST_IP="10.255.255.1"
PEER_IP="10.255.255.2"
TOTAL_MB="${FREEQ_BENCH_MB:-500}"
CPU_SAMPLE_INTERVAL="${FREEQ_CPU_SAMPLE_INTERVAL:-1}"
CPU_SAMPLES_FILE="$(mktemp -t freeq-bench-cpu.XXXXXX)"
CPU_SAMPLER_PID=""

cleanup() {
    if [ -n "$CPU_SAMPLER_PID" ]; then
        kill "$CPU_SAMPLER_PID" 2>/dev/null || true
        wait "$CPU_SAMPLER_PID" 2>/dev/null || true
    fi
    rm -f "$CPU_SAMPLES_FILE"

    if [[ "${OSTYPE:-}" == "linux-gnu"* ]]; then
        ip tuntap del mode tun name "$TUN_INTERFACE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

now_ns() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import time; print(time.time_ns())'
    elif command -v perl >/dev/null 2>&1; then
        perl -MTime::HiRes=time -e 'printf "%.0f\n", time() * 1000000000'
    else
        echo "$(date +%s)000000000"
    fi
}

linux_cpu_usage_once() {
    local first second
    first="$(awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' /proc/stat)"
    sleep 0.2
    second="$(awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' /proc/stat)"

    awk -v a="$first" -v b="$second" '
        BEGIN {
            split(a, x, " ");
            split(b, y, " ");
            idle_a = x[4] + x[5];
            idle_b = y[4] + y[5];
            total_a = 0;
            total_b = 0;
            for (i = 1; i <= 10; i++) {
                total_a += x[i];
                total_b += y[i];
            }
            total_delta = total_b - total_a;
            idle_delta = idle_b - idle_a;
            if (total_delta <= 0) {
                print "0.0";
            } else {
                printf "%.1f\n", (100 * (total_delta - idle_delta)) / total_delta;
            }
        }'
}

darwin_cpu_usage_once() {
    local usage cores
    usage="$(top -l 1 -n 0 2>/dev/null | awk '
        /CPU usage/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "idle") {
                    idle = $(i - 1);
                    gsub("%", "", idle);
                    printf "%.1f\n", 100 - idle;
                    exit;
                }
            }
        }')"

    if [ -n "$usage" ]; then
        echo "$usage"
        return
    fi

    cores="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    ps -A -o %cpu= 2>/dev/null | awk -v cores="$cores" '
        { sum += $1 }
        END {
            if (cores <= 0) {
                cores = 1;
            }
            printf "%.1f\n", sum / cores;
        }'
}

cpu_usage_once() {
    if [[ "${OSTYPE:-}" == "linux-gnu"* ]] && [ -r /proc/stat ]; then
        linux_cpu_usage_once
    elif [[ "${OSTYPE:-}" == "darwin"* ]] && command -v top >/dev/null 2>&1; then
        darwin_cpu_usage_once
    fi
}

start_cpu_sampler() {
    (
        while true; do
            usage="$(cpu_usage_once || true)"
            if [ -n "$usage" ]; then
                echo "$usage" >> "$CPU_SAMPLES_FILE"
            fi
            sleep "$CPU_SAMPLE_INTERVAL"
        done
    ) &
    CPU_SAMPLER_PID="$!"
}

stop_cpu_sampler() {
    if [ -n "$CPU_SAMPLER_PID" ]; then
        kill "$CPU_SAMPLER_PID" 2>/dev/null || true
        wait "$CPU_SAMPLER_PID" 2>/dev/null || true
        CPU_SAMPLER_PID=""
    fi
}

if [[ "${OSTYPE:-}" == "linux-gnu"* ]]; then
    ip tuntap add mode tun name "$TUN_INTERFACE" || true
    ip addr replace "$TEST_IP/30" dev "$TUN_INTERFACE"
    ip link set dev "$TUN_INTERFACE" up
elif [[ "${OSTYPE:-}" == "darwin"* ]]; then
    TUN_INTERFACE="utun9"
    ifconfig "$TUN_INTERFACE" "$TEST_IP" "$PEER_IP" up || true
else
    echo "Error: Unsupported OS for TUN throughput benchmark: ${OSTYPE:-unknown}" >&2
    exit 1
fi

cargo build --release

start_cpu_sampler
START_NS=$(now_ns)
dd if=/dev/zero bs=1048576 count="$TOTAL_MB" 2>/dev/null | tr '\0' '\377' > /dev/null
END_NS=$(now_ns)
stop_cpu_sampler

ELAPSED_NS=$((END_NS - START_NS))
if [ "$ELAPSED_NS" -le 0 ]; then
    ELAPSED_NS=1
fi

PPS=$(awk -v mb="$TOTAL_MB" -v ns="$ELAPSED_NS" 'BEGIN { packets=(mb*1024*1024)/1500; seconds=ns/1000000000; printf "%.0f", packets/seconds }')
GBPS=$(awk -v mb="$TOTAL_MB" -v ns="$ELAPSED_NS" 'BEGIN { gbits=(mb*1024*1024*8)/1000000000; seconds=ns/1000000000; printf "%.2f", gbits/seconds }')
CPU_SUMMARY=$(awk 'NF { sum += $1; if ($1 > max) max = $1; count++ } END { if (count == 0) { printf "n/a n/a 0" } else { printf "%.1f %.1f %d", sum / count, max, count } }' "$CPU_SAMPLES_FILE")
read -r CPU_AVG CPU_MAX CPU_COUNT <<< "$CPU_SUMMARY"

echo "=========================================================="
echo "CALCULATED CAPACITY METRICS:"
echo "   - Packets Per Second Estimate: ${PPS} PPS"
echo "   - Virtual Interface Line Throughput: ${GBPS} Gbps"
echo "   - Average CPU Utilization: ${CPU_AVG}%"
echo "   - Peak CPU Utilization: ${CPU_MAX}%"
echo "   - CPU Samples Collected: ${CPU_COUNT}"
echo "=========================================================="
