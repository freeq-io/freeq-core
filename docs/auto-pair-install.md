# FreeQ automatic pairing (no folder drop)

**Status:** preferred install/connect path  
**Goal:** node↔node or node↔gateway↔node without trading `~/FreeQ/01-send` / `02-put` peer files by hand.

Private keys never leave a node. Only **public** peer material is exchanged.

## State locations

| Path | Purpose |
|------|---------|
| `~/.freeq/perf/node.env` | Local identity env (private path ref) |
| `~/.freeq/perf/peer.env` | Local **public** peer material |
| `~/.freeq/peers/received/` | Peers installed by pair/invite |
| `~/.freeq/pair/` | Latest invite bundle/code |

Legacy `~/FreeQ/01-send-this-file` and `02-put-peer-file-here` remain optional mirrors only.

## Install

One-line installer (same as getfreeq.com; re-run anytime to update). Downloads
**prebuilt** macOS binaries from GitHub Releases (no cargo build):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
```

See [binary-releases.md](binary-releases.md). Or from a checkout / source build:

```bash
scripts/install/freeq-install-macos.sh
FREEQ_FROM_SOURCE=1 scripts/install/freeq-install-macos.sh
```

State lives under `~/.freeq/`. Binaries link to `~/.freeq/bin`. The installer
starts the local node and prints `freeq pair` next steps.

## Direct node → node (automatic exchange)

One side must accept a short-lived TCP pair port (8791 by default). Overlay UDP is separate (51820).

```bash
# Node A (reachable):
freeq pair host --code MYSECRET --port 8791 --auto-start

# Node B:
freeq pair join-host --url http://A_PUBLIC_IP:8791 --code MYSECRET --auto-start
```

What happens:

1. Nodes exchange **public** `peer.env` only (Bearer pair code).  
2. Material is written under `~/.freeq/peers/received/`.  
3. `--auto-start` renders config and starts freeqd (no drop folders).

### Alternate: API invite (bundle + code)

```bash
# A (freeqd must be running):
freeq pair invite --endpoint A_PUBLIC:51820
# → ~/.freeq/pair/invite-latest.json + code

# B (after receiving the JSON somehow — still no FreeQ folders):
freeq pair join --invite-file invite-latest.json --code CODE --auto-start
```

### Zero file trade when you have SSH

```bash
scripts/setup/freeq-orchestrate-macos.sh \
  --mode direct \
  --remote user@OTHER_HOST
```

## Gateway path: leaf → gateway → leaf

Leaves only need the **gateway** public peer material + remote overlay `/32`s.  
They do **not** need each other's peer.env for the basic gateway_client path.

```bash
# On each leaf (same gateway public bundle):
freeq pair gateway \
  --gateway-endpoint 18.225.246.90:51820 \
  --gateway-peer-env /path/or/https://url/to/aws-gateway-peer.env \
  --remote-overlay 10.66.0.2/32 \
  --auto-start
```

Publish the gateway public peer.env once (S3, HTTPS, or operator channel).  
Do not publish identity keys.

SSH orchestrator for leaf + gateway when SSH is available:

```bash
scripts/setup/freeq-orchestrate-macos.sh \
  --mode gateway \
  --remote user@leaf2 \
  --gateway ubuntu@gateway \
  --gateway-endpoint 18.225.246.90:51820
```

## Inspect

```bash
freeq pair show
freeq gateway status   # or freeq pair show
```

## What we deliberately stopped requiring

- Manually copying files into `~/FreeQ/02-put-peer-file-here`  
- Guessing which of several peer.env files in Downloads is correct  
- Treating “daemon running” as connected (pair + connect still need healthy sessions)

## Security notes

- Pair host is **short-lived** and single-guest; use a strong `--code`.  
- Prefer pairing on a trusted network or with a fresh code per session.  
- Gateway never dials leaves; leaves remain outbound-only in gateway mode.  
