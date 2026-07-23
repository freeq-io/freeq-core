# FreeQ macOS Setup Golden Path

This is the shortest expected path for Mac testers. It covers three operator
actions:

1. Start FreeQ.
2. Connect directly or through a reachable gateway when needed.
3. Roll FreeQ back and resume normal Mac networking.

## Both Testers

Install FreeQ:

```bash
brew install freeq
```

Prepare this Mac and start the local setup node:

```bash
freeq setup
```

Update FreeQ later with:

```bash
brew upgrade freeq
```

When prompted, enter this Mac's reachable UDP endpoint if you know it, for
example:

```text
your-host-or-ip:51820
```

Setup creates one visible folder:

```text
~/FreeQ
```

Do not browse hidden folders.

## Exchange Files

Send the file from:

```text
~/FreeQ/01-send-this-file
```

Put the file you receive into:

```text
~/FreeQ/02-put-peer-file-here
```

The received file supplies the peer name, overlay address, public keys, and
reachable endpoint.

## Validate

```bash
cd ~/freeq-core
scripts/setup/freeq-validate-peer-env.sh ~/FreeQ/02-put-peer-file-here/*.env
```

If validation says `FREEQ_PUBLIC_ENDPOINT` is missing, ask the other tester to
rerun setup with their reachable UDP endpoint and resend the file.

## Start

```bash
cd ~/freeq-core
scripts/setup/freeq-render-config.sh
scripts/setup/freeq-start-macos.sh
```

Leave that Terminal window open.

The start helper records FreeQ-owned macOS network changes in:

```text
~/.freeq/perf/freeq-network-state.env
```

If startup fails after `freeqd` is spawned, the helper automatically calls the
rollback helper to stop `freeqd`, remove FreeQ-owned routes, and renew DHCP.

## Connect Through A Gateway When Needed

Direct peer-to-peer may not work from hotel Wi-Fi, airport Wi-Fi, carrier-grade
NAT, Starlink, or locked-down enterprise guest networks. In that case, use a
reachable gateway or relay node as the peer.

The local Mac steps do not change:

1. Get the gateway or relay peer `.env` file.
2. Put it in `~/FreeQ/02-put-peer-file-here`.
3. Start or restart FreeQ:

```bash
freeq gateway
```

If there is an old FreeQ route or daemon from a previous run, `--restart` uses
the rollback helper before starting the replacement daemon.

## Roll Back To Normal Networking

Use this whenever you are done with FreeQ, before joining captive Wi-Fi, or any
time the Mac's network state looks strange:

```bash
freeq stop
```

Rollback does the host-network cleanup FreeQ owns:

- stops only a validated `freeqd` process from the FreeQ pid file
- removes only overlay host routes recorded in the rollback ledger
- restores Wi-Fi DHCP mode when FreeQ recorded DHCP before start
- renews DHCP on `en0` by default
- removes the rollback ledger after cleanup

The local helper remains available for advanced users:

```bash
cd ~/freeq-core
scripts/setup/freeq-stop-macos.sh --renew-dhcp
```

If rollback says no ledger exists, it falls back to older env-file cleanup for
pre-rollback FreeQ runs.

## Dry Run

To preview setup without installing, building, or writing files:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)" -- --dry-run
```
