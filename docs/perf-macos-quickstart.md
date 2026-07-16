# FreeQ Perf Test: macOS Quickstart

This guide sets up one Mac for a two-peer FreeQ Core performance test. Run the
same flow on both Macs.

## Requirements

- A Mac with internet access.
- Terminal.
- Rust installed. If `cargo --version` fails, install Rust first:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then open a new Terminal window.

## Step 1: Install

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/perf/freeq-perf-install-macos.sh)"
```

The installer derives the local node name from the Mac hostname and writes a
visible setup folder:

```text
~/FreeQ-Perf
~/FreeQ-Perf/freeq-perf.conf
~/FreeQ-Perf/01-send-this-file
~/FreeQ-Perf/02-put-peer-file-here
~/FreeQ-Perf/03-results
~/FreeQ-Perf/04-logs
```

Edit `~/FreeQ-Perf/freeq-perf.conf` if you need to override the generated node
name, overlay address, listen address, peer endpoint, or peer SSH settings.

## Step 2: Exchange Peer Files

Send the `.env` file from this folder to the other tester:

```text
~/FreeQ-Perf/01-send-this-file
```

When the other tester sends their `.env` file, put it here:

```text
~/FreeQ-Perf/02-put-peer-file-here
```

Do not send `identity.key`. You do not need to browse hidden folders.

## Step 3: Set Peer Endpoint

Open:

```text
~/FreeQ-Perf/freeq-perf.conf
```

Set:

```bash
FREEQ_PEER_ENDPOINT='PEER_HOST_OR_IP:51820'
```

If direct SSH benchmarks are needed, also set:

```bash
FREEQ_PEER_SSH_USER='remote-login-name'
FREEQ_PEER_SSH_PORT='22'
```

## Step 4: Render And Start

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-render-config.sh
scripts/perf/freeq-perf-start-macos.sh
```

Leave that Terminal window open.

## Step 5: Run Tests

Open a second Terminal window.

Overlay test:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh --mode freeq
```

Direct baseline, after `FREEQ_PEER_ENDPOINT`, `FREEQ_PEER_SSH_USER`, and
`FREEQ_PEER_SSH_PORT` are set in `freeq-perf.conf`:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh --mode direct
```

## Step 6: Bundle Results

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-bundle-results.sh
```

The archive will be created in:

```text
~/FreeQ-Perf/03-results
```

## If Something Fails

Run:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-preflight-macos.sh
```

Logs are written here:

```text
~/FreeQ-Perf/04-logs
```
