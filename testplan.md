# FreeQ Core - Test Plan

## Overview

This document outlines testing strategy for FreeQ, focusing on:
- Post-quantum security
- Battlefield / intermittent connectivity resilience
- Cross-platform compatibility (Linux, Windows, macOS)
- Non-invasive gateway behavior
- Performance and stability

**Last Updated:** May 2026

---

## 1. Test Environment

### Hardware
| Device              | OS Options              | Role                          | Notes |
|---------------------|-------------------------|-------------------------------|-------|
| Old Laptop 1        | Linux (RHEL 10 preferred) | Gateway A                     | Primary |
| Old Laptop 2        | Windows 10/11           | Gateway B                     | Interop |
| Mac Mini            | macOS                   | Management + Monitoring       | Dashboard |
| ESP32 (multiple)    | ESP-IDF / Rust          | Constrained client            | Future |
| Router / Switch     | Stock                   | Network                       | Simulate real enterprise nets |

### Software Stack
- FreeQ latest build
- Wireshark / tcpdump
- iperf3 / speedtest
- `jq`, `curl`, `htop`

---

## 2. Core Test Categories

### Phase 1: Basic Connectivity & Session Lifecycle

- [ ] Session creation (Idle → Discovering → Handshaking → Active)
- [ ] Normal handshake completion (full PQ)
- [ ] Graceful session termination
- [ ] Session state transitions logging/auditing
- [ ] SessionManager handling multiple concurrent sessions

### Phase 2: Battlefield / Intermittent Connectivity (High Priority)

- [ ] Connection loss → Suspended state
- [ ] Fast reconnect when back in range (drone scenario)
- [ ] Session resumption using tickets
- [ ] Long suspension (15–30 minutes) + reconnect
- [ ] High packet loss (10–40%) simulation
- [ ] Network flapping (on/off every 30 seconds)

### Phase 3: Security & Crypto

- [ ] Hybrid KEM + ML-DSA handshake verification
- [ ] Silent dropping of unauthenticated packets (cloaking)
- [ ] Replay attack resistance
- [ ] Forward secrecy validation
- [ ] Rekeying without disruption
- [ ] Invalid signature / malformed packet handling

### Phase 4: Platform & Interoperability

- [ ] Linux ↔ Linux
- [ ] Linux ↔ Windows
- [ ] macOS management plane
- [ ] TUN/TAP overlay mode
- [ ] Gateway mode (decrypt → forward to local port)

### Phase 5: Performance & Stability

- [ ] Throughput (iperf3 over FreeQ tunnel)
- [ ] Latency overhead
- [ ] Memory usage under load
- [ ] Long-duration stability (24h+)
- [ ] Resource usage on older hardware

---

## 3. Test Scenarios (Recommended Order)

1. **Basic Local Test** (same machine, loopback)
2. **Two-machine wired test**
3. **WiFi intermittent test** (turn WiFi on/off)
4. **Windows-Linux interop**
5. **High packet loss simulation** (`tc` or `clumsy`)
6. **Long-running drone simulation** (scripted disconnects)

---

## 4. Tooling & Commands

**Packet Capture:**
```bash
# Linux
sudo tcpdump -i any port 443 -w freeq.pcap

# Wireshark filter
freeq || quic || mlkem