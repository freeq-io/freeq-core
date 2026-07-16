# FreeQ macOS Setup Golden Path

This is the shortest expected path for two Mac testers.

## Both Testers

Run:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)"
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

## Dry Run

To preview setup without installing, building, or writing files:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/setup/freeq-setup-macos.sh)" -- --dry-run
```
