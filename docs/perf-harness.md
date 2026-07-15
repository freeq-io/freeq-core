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
FREEQ_REMOTE_SSH=patrickmccormick@REPLACE_WITH_PATRICK_HOST \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/perf/freeq-perf-install-macos.sh)"
```

Send this file back to Patrick over a trusted channel:

```text
~/.freeq/perf/node.env
```

## Patrick Mac Setup

On Patrick's Mac, run the same identity generation with Patrick's overlay
address:

```bash
cd /Users/patrickmccormick/Documents/FreeQ/freeq-core
cargo build --release -p freeqd -p freeq-perf-identity
target/release/freeq-perf-identity \
  --node-name patrick-mac \
  --overlay-address 10.66.0.1/24 \
  --listen 0.0.0.0:51820 \
  --output-dir ~/.freeq/perf
```

Send Patrick's `~/.freeq/perf/node.env` to the Florida tester.

## Render Configs

Each side renders a config using the other side's `node.env` and reachable UDP
endpoint.

On the Florida Mac:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-render-config.sh \
  --local-env ~/.freeq/perf/node.env \
  --peer-env ~/Downloads/patrick-node.env \
  --peer-endpoint REPLACE_WITH_PATRICK_HOST_OR_IP:51820
```

On Patrick's Mac:

```bash
cd /Users/patrickmccormick/Documents/FreeQ/freeq-core
scripts/perf/freeq-perf-render-config.sh \
  --local-env ~/.freeq/perf/node.env \
  --peer-env ~/Downloads/florida-node.env \
  --peer-endpoint REPLACE_WITH_FLORIDA_HOST_OR_IP:51820
```

## Start FreeQ

Both Macs need UDP `51820` reachable, or a different shared port if configured.
For the first test, run in foreground so logs are visible:

```bash
scripts/perf/freeq-perf-start-macos.sh --peer-env ~/Downloads/peer-node.env
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
  --target REPLACE_WITH_PATRICK_HOST_OR_IP \
  --ssh-user patrickmccormick \
  --ssh-port REPLACE_WITH_PATRICK_SSH_PORT \
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
