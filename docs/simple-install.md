# FreeQ Simple Install

This page is for a normal person installing FreeQ on a Mac.

The goal is simple:

1. Install FreeQ.
2. Start FreeQ.
3. Connect directly or through a reachable gateway when needed.
4. Roll FreeQ back and return the Mac to normal networking.

You do not need to edit files, set variables, open hidden folders, configure a
router, or run network commands.

## Mac Install

Open the Terminal app.

Install FreeQ with Homebrew:

```bash
brew install freeq
```

Then prepare this Mac and start the local setup node:

```bash
freeq setup
```

FreeQ may ask for this Mac's local admin password. That is normal. It does not
ask for another person's password.

When it is done, look for this line:

    FreeQ install result: PASS

If you see that line, FreeQ is installed and running.

## Updates

Use Homebrew to update FreeQ:

```bash
brew upgrade freeq
```

Homebrew updates the FreeQ binary, docs, and scripts together.

## Start, Connect, Roll Back

After install, use the local setup page when it opens:

```text
http://127.0.0.1:6789/
```

For the fallback file-exchange path, send your visible peer file from:

```text
~/FreeQ/01-send-this-file
```

Put the peer or gateway file you receive here:

```text
~/FreeQ/02-put-peer-file-here
```

Then start or restart FreeQ from Terminal:

```bash
freeq gateway
```

If direct peer-to-peer will not work because one side is on hotel Wi-Fi,
carrier-grade NAT, Starlink, or another restricted network, use a reachable
gateway or relay node as the peer file source. The local Mac flow is the same:
place the gateway peer file in `~/FreeQ/02-put-peer-file-here`, then run:

```bash
freeq gateway
```

To stop FreeQ and return this Mac to normal networking:

```bash
freeq stop
```

That rollback command stops only the FreeQ daemon, removes FreeQ-owned host
routes from the macOS rollback ledger, restores DHCP mode when FreeQ recorded
it, and asks macOS to renew Wi-Fi DHCP.

When rollback succeeds, look for:

```text
FreeQ rollback result: PASS
```

## What Success Means

Success means:

- FreeQ downloaded or updated.
- Homebrew installed or upgraded FreeQ.
- FreeQ built successfully.
- This Mac has a local FreeQ node identity.
- FreeQ started.
- The local FreeQ status check answered.
- FreeQ can be rolled back with `freeq stop`.

That is the only result a new installer needs to understand.

## If It Does Not Pass

If the installer does not show `PASS`, send the visible error text to the person
helping you.

Do not send private keys.
Do not send files from hidden `.freeq` folders.

## Linux, Windows, And Gateway Hardware

Mac install is first.

Linux install is next.

Windows and gateway hardware installers are planned, but they are not ready yet.
