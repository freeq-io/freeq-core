# FreeQ Core Perf Harness

This harness is for early alpha performance validation. It compares normal
internet traffic with traffic carried through a FreeQ overlay.

The first useful test matrix is:

1. Direct `iperf3` TCP between two Macs.
2. `iperf3` over the FreeQ overlay.
3. Direct `scp`/SSH file transfer.
4. `scp`/SSH through the FreeQ overlay.
5. SSH connection setup latency direct and through the overlay.

## macOS Setup

Use the generic macOS quickstart on each Mac:

```text
docs/perf-macos-quickstart.md
```

The setup is profile-driven. Machine-specific values live in:

```text
~/FreeQ/freeq-setup.conf
```

The installer derives `FREEQ_NODE_NAME` from the local hostname unless the
profile overrides it. The received peer file goes in:

```text
~/FreeQ/02-put-peer-file-here
```

The file to send to the other tester is created in:

```text
~/FreeQ/01-send-this-file
```

## Render Configs

After `FREEQ_PEER_ENDPOINT` is set in `~/FreeQ/freeq-setup.conf` and the
peer `.env` file is in the visible drop folder, run:

```bash
cd ~/freeq-core
scripts/setup/freeq-render-config.sh
```

The setup script can also be rerun at this point; it will detect the peer file
and endpoint, then offer to render and start FreeQ.

## Start FreeQ

Both Macs need UDP `51820` reachable, or a different listen port if configured.

```bash
cd ~/freeq-core
scripts/setup/freeq-start-macos.sh
```

## Run Direct Baseline

Start an `iperf3` server on the receiving Mac:

```bash
iperf3 -s
```

Then on the sending Mac, after `FREEQ_PEER_ENDPOINT`, `FREEQ_PEER_SSH_USER`, and
`FREEQ_PEER_SSH_PORT` are set in `~/FreeQ/freeq-setup.conf`:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh --mode direct
```

## Run FreeQ Overlay Leg

With `freeqd` running on both Macs:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh --mode freeq
```

Use `--mode both` only after both direct and overlay paths are known to work.

## Notes

- This is an alpha validation harness, not a final product benchmark.
- Internet routing, Wi-Fi, NAT, and ISP shaping can dominate results.
- Run at least three samples per mode before drawing conclusions.
- Record CPU, memory, and whether either Mac was thermally constrained.
- If direct SSH works but overlay SSH fails, validate route/interface state
  before interpreting it as a performance issue.
