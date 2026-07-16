# FreeQ Core Perf Harness

This harness is for early alpha performance validation. It compares normal
internet traffic with traffic carried through a FreeQ overlay.

The first useful test matrix is:

1. Direct `iperf3` TCP between Macs.
2. `iperf3` over the FreeQ overlay.
3. Direct `scp`/SSH file transfer.
4. `scp`/SSH through the FreeQ overlay.
5. SSH connection setup latency direct and through the overlay.

## Florida Mac Install

For David, use the short field guide:

```text
docs/perf-david-quickstart.md
```

On the Florida Mac, the easiest path is to run the installer directly from
GitHub. It clones or updates the repo for him:

```bash
FREEQ_NODE_NAME=david-florida-mac \
FREEQ_OVERLAY_ADDRESS=10.66.0.2/24 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/perf/freeq-perf-install-macos.sh)"
```

Send this file back to Patrick over a trusted channel:

```text
~/FreeQ-Perf/01-send-this-file/david-florida-mac-peer.env
```

## Patrick Mac Setup

On Patrick's Mac, use the same visible-folder installer flow with Patrick's
overlay address:

```bash
cd /Users/patrickmccormick/Documents/FreeQ/freeq-core
FREEQ_NODE_NAME=patrick-mac \
FREEQ_OVERLAY_ADDRESS=10.66.0.1/24 \
scripts/perf/freeq-perf-install-macos.sh
```

Send Patrick's visible peer exchange file to the Florida tester:

```text
~/FreeQ-Perf/01-send-this-file/patrick-mac-peer.env
```

## Render Configs

Each side renders a config using its local identity, the other side's `peer.env`,
and the other side's reachable UDP endpoint. Put the received `peer.env` file in:

```text
~/FreeQ-Perf/02-put-peer-file-here
```

On the Florida Mac:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-render-config.sh \
  --peer-endpoint ACTUAL_PATRICK_HOST_OR_IP:51820
```

On Patrick's Mac:

```bash
cd /Users/patrickmccormick/Documents/FreeQ/freeq-core
scripts/perf/freeq-perf-render-config.sh \
  --peer-endpoint ACTUAL_FLORIDA_HOST_OR_IP:51820
```

## Start FreeQ

Both Macs need UDP `51820` reachable, or a different shared port if configured.
For the first test, run in foreground so logs are visible:

```bash
scripts/perf/freeq-perf-start-macos.sh
```

## Run Direct Baseline

Start an `iperf3` server on Patrick's Mac:

```bash
iperf3 -s
```

Then on the Florida Mac:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh \
  --mode direct \
  --target ACTUAL_PATRICK_HOST_OR_IP \
  --ssh-user patrickmccormick \
  --ssh-port ACTUAL_PATRICK_SSH_PORT \
  --label florida-to-patrick-direct
```

## Run FreeQ Overlay Leg

With `freeqd` running on both Macs, run:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh \
  --mode freeq \
  --overlay-host 10.66.0.1 \
  --ssh-user patrickmccormick \
  --label florida-to-patrick-freeq
```

Use `--mode both` only after both direct and overlay paths are known to work.

## Notes

- This is an alpha validation harness, not a final product benchmark.
- Internet routing, Wi-Fi, NAT, and ISP shaping can dominate results.
- Run at least three samples per mode before drawing conclusions.
- Record CPU, memory, and whether either Mac was thermally constrained.
- If direct SSH works but overlay SSH fails, validate route/interface state
  before interpreting it as a performance issue.
