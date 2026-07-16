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

To preview setup without installing, building, or writing files, add
`--dry-run`:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)" -- --dry-run
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
name, overlay address, listen address, this Mac's public endpoint, or peer SSH
settings.

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

## Step 3: Endpoint Handling

The peer name comes from the `.env` file you receive. You do not need to know
or type it.

Each tester should enter this Mac's reachable UDP endpoint during setup. That
value is written into the `.env` file they send you as `FREEQ_PUBLIC_ENDPOINT`.
No peer endpoint is typed on the receiving Mac.

If the sender left `FREEQ_PUBLIC_ENDPOINT` blank, ask them to rerun setup with
their reachable UDP endpoint and resend their `.env` file.

You can validate the received file before rendering:

```bash
cd ~/freeq-core
scripts/setup/freeq-validate-peer-env.sh ~/FreeQ/02-put-peer-file-here/*.env
```

If direct SSH benchmarks are needed, also set:

```bash
FREEQ_PEER_SSH_USER='remote-login-name'
FREEQ_PEER_SSH_PORT='22'
```

## Step 4: Render And Start

After the peer file is in the drop folder, you can rerun the setup script and
answer yes when it offers to render and start:

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

Direct baseline, after the peer endpoint is available from the peer file and
`FREEQ_PEER_SSH_USER` and `FREEQ_PEER_SSH_PORT` are set in `freeq-setup.conf`:

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
