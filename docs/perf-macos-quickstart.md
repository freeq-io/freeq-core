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
brew install freeq
```

Prepare this Mac and start the local setup node:

```bash
freeq setup
```

Update FreeQ later with `brew upgrade freeq`.

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

FreeQ records the macOS network changes it owns in an internal rollback ledger.
That ledger is used later to remove only FreeQ-owned routes.

## Gateway Or Relay Path

If the two Macs can reach each other directly, use the direct peer file. A gateway is not required for direct node-to-node FreeQ.

If the two Macs cannot connect directly because one side is on hotel Wi-Fi,
airport Wi-Fi, carrier-grade NAT, Starlink, cellular, or another restricted
network, use a reachable gateway or relay peer file instead of a direct peer
file.

The current AWS field gateway is the hardened accept-only gateway binary:

```text
service: freeq-gateway.service
listen:  UDP 51820
status:  http://127.0.0.1:6790/status on the gateway host
```

Do not start the legacy `freeqd.service` on the gateway for this path. It uses
the same UDP port and will fail while `freeq-gateway.service` is active.

The local steps are the same:

```bash
cd ~/freeq-core
cp /path/to/gateway-peer.env ~/FreeQ/02-put-peer-file-here/
freeq gateway status
freeq doctor
freeq gateway
freeq status
```

`freeq gateway` rolls back any previous FreeQ daemon and FreeQ-owned routes
before starting the new connection.

Quick bidirectional smoke test:

```bash
scripts/perf/freeq-bidirectional-smoke-macos.sh
```

That tests local-to-gateway overlay reachability and prints the command to run
from the gateway for the return path. If you have SSH access to the gateway,
run the full return-path test from this Mac:

```bash
scripts/perf/freeq-bidirectional-smoke-macos.sh --ssh-user ubuntu
```

For client-to-client data through a gateway, use opaque relay mode so the
gateway forwards ciphertext without holding the end-to-end payload key. Generate
one 32-byte key on one client, send it to the other client over a trusted side
channel, and set it only on the two endpoint Macs:

```bash
openssl rand -base64 32
export FREEQ_E2E_RELAY_KEY_B64='<the-shared-client-key>'
export FREEQ_EXTRA_ALLOWED_IPS='<other-client-overlay-ip>/32'
freeq gateway connect
```

Do not set `FREEQ_E2E_RELAY_KEY_B64` on the gateway. The gateway only needs
routes for each client overlay IP.

For the field helper script, place `aws-gateway-peer.env` in the repo root,
current directory, or `~/Downloads`. The script imports it into the runtime
location automatically.

Local Mac example:

```bash
cd ~/freeq-core
export FREEQ_E2E_RELAY_KEY_B64='<the-shared-client-key>'
FREEQ_SUDO_CACHE_SECONDS=180 \
scripts/field/freeq-leaf-connect-gateway-macos.sh \
  --remote-overlay 10.66.0.165/32
```

Other Mac example:

```bash
cd ~/freeq-core
export FREEQ_E2E_RELAY_KEY_B64='<the-shared-client-key>'
FREEQ_SUDO_CACHE_SECONDS=180 \
scripts/field/freeq-leaf-connect-gateway-macos.sh \
  --remote-overlay 10.66.0.1/32
```

## Step 5: Run Tests

Open a second Terminal window.

Overlay test:

```bash
cd ~/freeq-core
scripts/perf/freeq-perf-run.sh --mode freeq
```

Gateway-path evidence run, after both sides can ping each other over overlay:

```bash
cd ~/freeq-core
scripts/perf/freeq-gateway-path-perf.sh \
  --remote-overlay-ip <other-mac-overlay-ip> \
  --label "$(hostname -s)-gateway-$(date -u +%Y%m%dT%H%M%SZ)"
```

The hardened gateway is an accept-only relay. Leaf-to-leaf overlay ping and
iperf are the success criteria. Public gateway ICMP and gateway overlay ICMP are
optional diagnostics and may show 100% loss when host ICMP is blocked or the
gateway does not expose an overlay echo path. Add these only when you
intentionally want those probes:

```bash
  --gateway-public-host 18.225.246.90 \
  --gateway-overlay-ip 10.66.0.254
```

For UDP throughput, start an iperf3 server on the remote Mac first:

```bash
iperf3 -s
```

Then run the gateway-path evidence command from the local Mac. Repeat in the
opposite direction by swapping local and remote roles.

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

## Roll Back And Resume Normal Networking

When the test is done, before joining captive Wi-Fi, or whenever normal Mac
networking looks wrong, run:

```bash
freeq stop
```

This stops the validated FreeQ daemon, removes FreeQ-owned overlay host routes,
restores recorded DHCP mode, renews Wi-Fi DHCP, and deletes the rollback ledger.
Do not use raw `sudo kill` as the normal stop path; it stops the process but can
leave host-network state behind.

The local helper remains available after install:

```bash
cd ~/freeq-core
scripts/setup/freeq-stop-macos.sh --renew-dhcp
```
