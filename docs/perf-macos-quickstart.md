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
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)"
```

The installer asks a few setup questions. Press Return to accept the defaults.
The local node name defaults to the Mac hostname. The installer writes a visible
setup folder:

```text
~/FreeQ
~/FreeQ/freeq-setup.conf
~/FreeQ/01-send-this-file
~/FreeQ/02-put-peer-file-here
~/FreeQ/03-perf-results
~/FreeQ/04-logs
```

Edit `~/FreeQ/freeq-setup.conf` if you need to override the generated node
name, overlay address, listen address, peer endpoint, or peer SSH settings.

If a dependency is missing, the installer prints the install command and may ask
whether to run it. Answer `y` to let setup continue, or `n` to install it
yourself and rerun the setup script later.

## Step 2: Exchange Peer Files

Send the `.env` file from this folder to the other tester:

```text
~/FreeQ/01-send-this-file
```

When the other tester sends their `.env` file, put it here:

```text
~/FreeQ/02-put-peer-file-here
```

Do not send `identity.key`. You do not need to browse hidden folders.

## Step 3: Set Peer Endpoint

Open:

```text
~/FreeQ/freeq-setup.conf
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

After the peer file is in the drop folder and `FREEQ_PEER_ENDPOINT` is set, you
can rerun the setup script and answer yes when it offers to render and start:

```bash
cd ~/freeq-core
scripts/setup/freeq-setup-macos.sh
```

Or run the two setup commands directly:

```bash
cd ~/freeq-core
scripts/setup/freeq-render-config.sh
scripts/setup/freeq-start-macos.sh
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
`FREEQ_PEER_SSH_PORT` are set in `freeq-setup.conf`:

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
~/FreeQ/03-perf-results
```

## If Something Fails

Run:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-preflight-macos.sh
```

Logs are written here:

```text
~/FreeQ/04-logs
```
