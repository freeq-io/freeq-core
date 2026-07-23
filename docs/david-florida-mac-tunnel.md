# Florida Mac-To-Mac Field Runbook

Goal: connect a Florida Mac behind Starlink to a reachable Mac over a two-node FreeQ tunnel without hidden-folder browsing, SSH password sharing, or hand-built config files.

This runbook uses the new visible setup folder:

```text
~/FreeQ
~/FreeQ/01-send-this-file
~/FreeQ/02-put-peer-file-here
~/FreeQ/freeq-setup.conf
```

No one should send `identity.key`. No one should need to open `.freeq` in Finder.

## Field Result: 2026-07-17

The first successful field exercise established a FreeQ peer session from a
Starlink residential Mac to a reachable Mac with UDP `51820` forwarded.

Reachable node status:

```json
{
  "name": "patrick-mac",
  "peer_count": 1,
  "tunnel_count": 1,
  "packets_ingested": 12,
  "encrypted_bytes": 1200,
  "transport_frames": 12,
  "route_misses": 0,
  "last_error": null
}
```

Reachable node log:

```json
{"message":"inbound peer session established","peer":"davids-macbook-pro"}
```

Starlink-side node status:

```json
{
  "name": "davids-macbook-pro",
  "peer_count": 1,
  "tunnel_count": 1,
  "packets_ingested": 8,
  "encrypted_bytes": 800,
  "transport_frames": 8,
  "route_misses": 0,
  "last_error": null
}
```

Starlink-side node log:

```json
{"message":"establishing outbound peer session","peer":"patrick-mac","endpoint":"136.46.40.139:51820"}
{"message":"outbound peer session established","peer":"patrick-mac","endpoint":"136.46.40.139:51820"}
```

Conclusion:

- Starlink residential/CGNAT prevented direct inbound connectivity to the
  Starlink-side node.
- The Starlink-side node could still initiate outbound to the reachable node.
- FreeQ successfully authenticated the peer session and processed tunnel
  packets in the outbound-to-reachable direction.
- The installer and setup UI need first-class node capability labels so users
  understand whether a peer can initiate outbound, accept inbound direct UDP,
  or needs relay/rendezvous support.

## Node Capability Model

The field lesson is that "peer configured" is not enough. The setup flow should
classify each node by direct network capability:

| Capability | Meaning | Example |
|------------|---------|---------|
| `outbound-only` | Node can initiate to a reachable peer but cannot accept direct inbound UDP | Residential Starlink behind CGNAT |
| `inbound-reachable` | Node can accept direct inbound UDP from peers | Home/office router forwarding UDP `51820` |
| `bidirectional-direct` | Node can both initiate outbound and accept inbound direct UDP | Public IP or correctly forwarded router on both sides |
| `relay-required` | Direct peer-to-peer is not expected to work; use rendezvous/relay | CGNAT-to-CGNAT, locked enterprise guest Wi-Fi |

The setup website should show these labels per peer instead of only `peer_count`
and `tunnel_count`. A `receive-only` node is possible in narrow gateway designs,
but it is not the normal end-user shape. Most product decisions should be based
on inbound reachability and outbound initiation, not on packet send/receive
words alone.

## Before You Start

The simplest direct test needs at least one reachable UDP endpoint for FreeQ,
normally UDP `51820`.

For Patrick's Mac, confirm the public endpoint that David can reach. If Patrick's public IP is still `136.46.40.139` and UDP `51820` is forwarded to this Mac, use:

```text
136.46.40.139:51820
```

If the router forwards a different external UDP port, use:

```text
136.46.40.139:<external-udp-port>
```

Do not use the SSH port unless UDP `51820` is actually forwarded there. SSH and FreeQ are separate.

## Patrick Side

On Patrick's Mac:

```bash
cd ~/freeq-core
```

Open the visible setup profile:

```bash
open ~/FreeQ/freeq-setup.conf
```

Set these values:

```bash
FREEQ_NODE_NAME='patrick-mac'
FREEQ_OVERLAY_ADDRESS='10.66.0.1/24'
FREEQ_LISTEN_ADDR='0.0.0.0:51820'
FREEQ_PUBLIC_ENDPOINT='136.46.40.139:51820'
```

Adjust `FREEQ_PUBLIC_ENDPOINT` if the real reachable UDP endpoint is different.

Refresh Patrick's visible peer file:

```bash
scripts/setup/freeq-setup-macos.sh
```

Send David this file:

```text
~/FreeQ/01-send-this-file/patrick-mac-peer.env
```

That file is safe to send. It contains Patrick's node name, overlay address, public endpoint, and public keys. It does not contain Patrick's private identity key.

## Starlink/CGNAT Side

The Starlink-side tester should run this in Terminal:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)"
```

When prompted, the Starlink-side tester should use:

```text
Local node name: david-florida-mac
Local overlay address: 10.66.0.2/24
Local listen address: 0.0.0.0:51820
This Mac's reachable UDP endpoint to share: <david-public-host-or-ip>:51820
Peer SSH user for optional benchmarks: leave blank
```

If the Starlink-side tester does not have a public inbound endpoint, leave the
reachable UDP endpoint blank and treat that node as `outbound-only`. It can
initiate to the reachable node, but the reachable node should not expect direct
inbound connectivity back to the Starlink-side node without relay/rendezvous or
a public IP service.

David's installer creates:

```text
~/FreeQ/01-send-this-file/david-florida-mac-peer.env
~/FreeQ/02-put-peer-file-here
~/FreeQ/freeq-setup.conf
```

David should put Patrick's file here:

```text
~/FreeQ/02-put-peer-file-here/patrick-mac-peer.env
```

David should send Patrick this file:

```text
~/FreeQ/01-send-this-file/david-florida-mac-peer.env
```

## Reachable Node Receives The Starlink-Side File

Patrick should put David's file here:

```text
~/FreeQ/02-put-peer-file-here/<david-node-name>-peer.env
```

The exact filename may reflect David's actual Mac name, for example
`davids-macbook-pro-peer.env`. The scripts accept any single `.env` file in
the visible drop folder and validate the node name from the file contents.

Validate it:

```bash
cd ~/freeq-core
scripts/field/freeq-patrick-start-for-david-macos.sh --check-peer-file
```

If validation says `FREEQ_PUBLIC_ENDPOINT` is blank or a placeholder, David needs to update `~/FreeQ/freeq-setup.conf`, rerun setup, and resend his peer file.

## Start The Tunnel

Run this on both Macs after each side has exactly one peer `.env` file in `~/FreeQ/02-put-peer-file-here`.

```bash
cd ~/freeq-core
scripts/setup/freeq-connect-macos.sh
```

The connect script validates the peer file, renders the config, starts `freeqd`, and configures the Mac `utun` interface.

For this Patrick/David field exercise, use the role-specific helpers instead:

Patrick:

```bash
cd ~/freeq-core
scripts/field/freeq-patrick-start-for-david-macos.sh
```

David:

```bash
cd ~/freeq-core
scripts/field/freeq-david-connect-to-patrick-macos.sh
```

These helpers still use the same generic setup engine, but they make the expected file names obvious:

```text
Patrick puts David's file here:
  ~/FreeQ/02-put-peer-file-here/<david-node-name>-peer.env

David puts Patrick's file here:
  ~/FreeQ/02-put-peer-file-here/<patrick-node-name>-peer.env
```

Each helper also has a check-only mode that detects and validates the peer file
without starting FreeQ or asking for sudo:

```bash
scripts/field/freeq-patrick-start-for-david-macos.sh --check-peer-file
scripts/field/freeq-david-connect-to-patrick-macos.sh --check-peer-file
```

If the expected peer file has not arrived yet, the helper prints the exact
visible folder to use and starts that Mac in listen-only mode with a valid
zero-peer config. That lets the node come up and keep its local API available
while the file exchange finishes. After the peer file arrives, rerun the same
helper to restart from listen-only mode into the full two-node tunnel config.

If you need to run the lower-level steps manually:

```bash
scripts/setup/freeq-render-config.sh
scripts/setup/freeq-start-macos.sh
```

The start step uses `sudo` to open and configure the Mac `utun` interface. David should enter David's local Mac admin password. Patrick should enter Patrick's local Mac admin password.

No one should ever enter the other person's SSH password.

Leave the FreeQ Terminal window open.

## Quick Checks

On each Mac:

```bash
curl -s http://127.0.0.1:6789/v1/status
```

The reachable node can try the Starlink-side overlay address, but this is
expected to fail or partially fail when the Starlink-side node is
`outbound-only`:

```bash
ping 10.66.0.2
```

The Starlink-side node should initiate the most meaningful direct test:

```bash
ping 10.66.0.1
```

## Stop

On either Mac:

```bash
scripts/setup/freeq-stop-macos.sh
```

On captive Wi-Fi, use the cleanup form so macOS renews DHCP after FreeQ removes
the overlay host routes:

```bash
scripts/setup/freeq-stop-macos.sh --renew-dhcp
```

The macOS start helper records FreeQ-owned network changes in
`~/.freeq/perf/freeq-network-state.env`. The stop helper uses that rollback
ledger so it removes only routes FreeQ added during startup.

## If It Asks For Patrick's SSH Password

Stop. That is not required for tunnel setup.

That prompt usually means an old direct SSH benchmark path is being used. For tunnel bring-up, leave the optional peer SSH user blank and use:

```bash
scripts/setup/freeq-render-config.sh
scripts/setup/freeq-start-macos.sh
```

Direct SSH benchmarks can be tested later, after the FreeQ overlay is working.

## Current Cloaking Boundary

The current field scripts start the existing direct-QUIC daemon path. FreeQ still performs peer authentication before a tunnel is trusted, and unauthenticated FreeQ-layer traffic is silently dropped, but full transport invisibility against random UDP or generic QUIC probes requires the pre-QUIC UDP admission gate planned in the strict cloaking workstream.

Until that gate is implemented, do not describe this field tunnel as fully transport-cloaked. It is a functional two-node FreeQ tunnel bring-up path for Patrick and David.

## What To Send

Patrick sends David:

```text
~/FreeQ/01-send-this-file/patrick-mac-peer.env
```

David sends Patrick:

```text
~/FreeQ/01-send-this-file/david-florida-mac-peer.env
```

Do not send:

```text
identity.key
node.env
anything from ~/.freeq
```
