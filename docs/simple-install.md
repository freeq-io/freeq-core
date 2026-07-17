# FreeQ Simple Install

This page is for a normal person installing FreeQ on a Mac.

The goal is simple:

1. Install FreeQ.
2. Start FreeQ.
3. See one clear result.

You do not need to edit files, set variables, open hidden folders, configure a
router, or run network commands.

## Mac Install

Open the Terminal app.

Copy this one line, paste it into Terminal, and press Return:

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"

The installer may ask for this Mac's local admin password. That is normal. It
does not ask for another person's password.

When it is done, look for this line:

    FreeQ install result: PASS

If you see that line, FreeQ is installed and running.

## What Success Means

Success means:

- FreeQ downloaded or updated.
- FreeQ built successfully.
- This Mac has a local FreeQ node identity.
- FreeQ started.
- The local FreeQ status check answered.

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
