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

Open the Terminal app. Paste this one-line installer (same command as
[getfreeq.com](https://getfreeq.com)):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
```

That command:

- Downloads **prebuilt binaries** for your Mac (Apple Silicon or Intel) from
  GitHub Releases — **no Rust/cargo compile step**
- Installs under `~/.freeq/dist` and links `~/.freeq/bin`
- Creates local identity under `~/.freeq/` (private keys stay local)
- Starts the local node and opens `http://127.0.0.1:6789/`

FreeQ may ask for this Mac's local admin password. That is normal. It does not
ask for another person's password.

When it is done, look for this line:

    FreeQ install result: PASS

If you see that line, FreeQ is installed and running.

Add binaries to your shell PATH (once):

```bash
echo 'export PATH="$HOME/.freeq/bin:$PATH"' >> ~/.zprofile
export PATH="$HOME/.freeq/bin:$PATH"
```

Pin a version or use source build only if you need to:

```bash
FREEQ_VERSION=v0.2.1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
FREEQ_FROM_SOURCE=1  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
```

## Updates

Re-run the same one-line installer any time. It downloads the latest release
binaries and restarts the local node.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-macos.sh)"
```

## Start, Connect, Roll Back

**Preferred:** automatic peer exchange under `~/.freeq/` (no folder drop).
Private keys never leave a node. Only public peer material is exchanged.
Details: [auto-pair-install.md](auto-pair-install.md).

### Direct node ↔ node

```bash
# Reachable Mac A:
freeq pair host --code SECRET --port 8791 --auto-start

# Mac B:
freeq pair join-host --url http://A_PUBLIC_IP:8791 --code SECRET --auto-start
```

### Gateway leaf (Starlink / CGNAT)

```bash
freeq pair gateway \
  --gateway-endpoint GATEWAY_IP:51820 \
  --gateway-peer-env /path/or/URL/to/gateway-peer.env \
  --remote-overlay OTHER_LEAF_OVERLAY/32 \
  --auto-start
```

### SSH orchestrator (zero file trade when you have SSH)

From a FreeQ Core checkout on the controlling Mac:

```bash
scripts/setup/freeq-orchestrate-macos.sh \
  --mode direct \
  --remote user@REMOTE_MAC_IP
```

That command prepares both Macs, exchanges only public peer files over SSH,
renders concrete configs, restarts FreeQ on both sides, and finishes with one
result:

```text
FreeQ orchestration result: PASS
```

If the remote checkout is missing, add `--sync-source`. If the SSH host is not
the same address FreeQ should dial, pass `--remote-endpoint HOST:51820`. If the
remote Mac cannot dial this Mac's detected Wi-Fi address, pass
`--local-endpoint HOST:51820`.

### Local status

```bash
freeq pair show
freeq doctor
freeq status
freeq gateway status
```

The local setup page after FreeQ starts:

```text
http://127.0.0.1:6789/
```

Legacy folder drop is optional only. If you still use files, send public
`peer.env` from `~/FreeQ/01-send-this-file` and place received peer or gateway
files in `~/FreeQ/02-put-peer-file-here`, then run `freeq gateway` / `freeq status`.
Prefer `freeq pair` instead.

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

- FreeQ downloaded or updated under `~/freeq-core`.
- FreeQ built successfully.
- This Mac has a local FreeQ node identity under `~/.freeq/`.
- FreeQ started and the local status check answered.
- Peers can be connected with `freeq pair` (no folder drop required).
- FreeQ can be rolled back with `freeq stop`.

That is the only result a new installer needs to understand.

## If It Does Not Pass

If the installer does not show `PASS`, send the visible error text to the person
helping you.

Do not send private keys.
Do not send files from `~/.freeq/` identity or key paths.

## Linux Install (Ubuntu / Debian-class)

### Default: portable GitHub binary (recommended for most nodes)

On the Linux host (e.g. `freeq.local`):

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash
```

That downloads the matching **portable** prebuilt package from GitHub Releases,
installs under `~/.freeq/`, and starts `freeqd`. No Rust toolchain required.
You may be prompted for sudo once (TUN / CAP_NET_ADMIN).

Accept-only **gateway** role (still uses the portable binary by default):

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh \
  | FREEQ_ROLE=gateway FREEQ_PUBLIC_ENDPOINT=freeq.local:51820 bash
```

From your laptop over SSH (use `-t` if sudo needs a password):

```bash
ssh -t you@freeq.local 'curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash'
```

### Optional: native source build (high throughput or gateway)

Portable release binaries are not tuned to a specific CPU. If this node will
carry **high packet rate** or act as a **busy gateway**, you can compile on the
machine itself with `target-cpu=native` (better crypto/PQC codegen on that
host). Tradeoffs: needs Rust, slower install, binary is **not portable** to
other CPUs.

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh \
  | FREEQ_FROM_SOURCE=1 bash

# Gateway + native
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh \
  | FREEQ_FROM_SOURCE=1 FREEQ_ROLE=gateway FREEQ_PUBLIC_ENDPOINT=freeq.local:51820 bash
```

`FREEQ_NATIVE=0` disables `-C target-cpu=native` while still building from source.

Read-only host inspection:

```bash
curl -fsSL https://raw.githubusercontent.com/freeq-io/freeq-core/main/scripts/install/freeq-install-linux.sh | bash -s -- --preflight
```

See also [binary-releases.md](binary-releases.md). The multi-distro acceptance
matrix is tracked in [Linux Support Acceptance](linux-supported-acceptance.md).

## Windows And Gateway Hardware

Windows installers are planned, but they are not ready yet.
