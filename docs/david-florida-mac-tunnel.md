# David Florida Mac Tunnel Runbook

Goal: connect David's Florida Mac to Patrick's Mac over a two-node FreeQ tunnel without hidden-folder browsing, SSH password sharing, or hand-built config files.

This runbook uses the new visible setup folder:

```text
~/FreeQ
~/FreeQ/01-send-this-file
~/FreeQ/02-put-peer-file-here
~/FreeQ/freeq-setup.conf
```

No one should send `identity.key`. No one should need to open `.freeq` in Finder.

## Before You Start

Both Macs need a reachable UDP endpoint for FreeQ, normally UDP `51820`.

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

## David Side

David should run this in Terminal:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)"
```

When prompted, David should use:

```text
Local node name: david-florida-mac
Local overlay address: 10.66.0.2/24
Local listen address: 0.0.0.0:51820
This Mac's reachable UDP endpoint to share: <david-public-host-or-ip>:51820
Peer SSH user for optional benchmarks: leave blank
```

If David does not yet know his reachable UDP endpoint, he can leave it blank for install, but he must set it before sending his peer file back. The receiving Mac cannot render a working config from a peer file with a blank `FREEQ_PUBLIC_ENDPOINT`.

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

## Patrick Receives David's File

Patrick should put David's file here:

```text
~/FreeQ/02-put-peer-file-here/david-florida-mac-peer.env
```

Validate it:

```bash
cd ~/freeq-core
scripts/setup/freeq-validate-peer-env.sh ~/FreeQ/02-put-peer-file-here/david-florida-mac-peer.env
```

If validation says `FREEQ_PUBLIC_ENDPOINT` is blank or a placeholder, David needs to update `~/FreeQ/freeq-setup.conf`, rerun setup, and resend his peer file.

## Start The Tunnel

Run this on both Macs after each side has exactly one peer `.env` file in `~/FreeQ/02-put-peer-file-here`.

```bash
cd ~/freeq-core
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

Patrick should be able to test David's overlay address:

```bash
ping 10.66.0.2
```

David should be able to test Patrick's overlay address:

```bash
ping 10.66.0.1
```

## Stop

On either Mac:

```bash
sudo kill "$(cat ~/.freeq/perf/freeqd.pid)"
```

## If It Asks For Patrick's SSH Password

Stop. That is not required for tunnel setup.

That prompt usually means an old direct SSH benchmark path is being used. For tunnel bring-up, leave the optional peer SSH user blank and use:

```bash
scripts/setup/freeq-render-config.sh
scripts/setup/freeq-start-macos.sh
```

Direct SSH benchmarks can be tested later, after the FreeQ overlay is working.

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
