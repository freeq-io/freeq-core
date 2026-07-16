# FreeQ Perf Test: David Quickstart

This guide sets up David's Florida Mac for a Patrick-to-David FreeQ Core
performance test.

## What David Needs

- A Mac with internet access.
- Terminal.
- Rust installed. If `cargo --version` fails, install Rust first:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then open a new Terminal window.

## Step 1: Install FreeQ Core

```bash
FREEQ_NODE_NAME=david-florida-mac \
FREEQ_OVERLAY_ADDRESS=10.66.0.2/24 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/perf/freeq-perf-install-macos.sh)"
```

This creates:

```text
~/freeq-core
~/.freeq/perf/node-exchange.json
~/.freeq/perf/node.env
~/.freeq/perf/peer.env
```

## Step 2: Send Patrick One File

Send this file to Patrick over a trusted channel:

```text
~/.freeq/perf/peer.env
```

Do not send:

```text
~/.freeq/perf/node.env
~/.freeq/perf/identity.key
```

## Step 3: Save Patrick's File

Patrick sends back his `peer.env`. Save it as:

```text
~/Downloads/patrick-peer.env
```

## Step 4: Render David's FreeQ Config

Patrick should provide his reachable UDP host or IP.

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-render-config.sh \
  --local-env ~/.freeq/perf/node.env \
  --peer-env ~/Downloads/patrick-peer.env \
  --peer-endpoint ACTUAL_PATRICK_HOST_OR_IP:51820
```

## Step 5: Start FreeQ

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-start-macos.sh --peer-env ~/Downloads/patrick-peer.env
```

Leave that Terminal window open.

## Step 6: Run The FreeQ Test

Open a second Terminal window:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh \
  --mode freeq \
  --overlay-host 10.66.0.1 \
  --ssh-user patrickmccormick \
  --label david-to-patrick-freeq
```

For the direct baseline over a non-standard forwarded SSH port:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh \
  --mode direct \
  --target ACTUAL_PATRICK_HOST_OR_IP \
  --ssh-user patrickmccormick \
  --ssh-port ACTUAL_PATRICK_SSH_PORT \
  --label david-to-patrick-direct
```

## Step 7: Bundle Results

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-bundle-results.sh david-to-patrick
```

Send Patrick the archive printed by the command.

## If Something Fails

Run:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-preflight-macos.sh
```

Then send Patrick:

```text
~/.freeq/perf/preflight-*.log
```
