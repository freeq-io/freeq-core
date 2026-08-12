# FreeQ automatic pairing (zero human `.env` trading)

**Status:** preferred install/connect path for FreeQ Core  
**Rule:** private keys never leave a node. Only **public** peer material is exchanged, and that exchange is automated (HTTP pair, invite API, or URL fetch)—operators do not email or Airdrop `.env` files.

## State locations

| Path | Purpose |
|------|---------|
| `~/.freeq/perf/node.env` | Local identity refs (private key path) |
| `~/.freeq/perf/peer.env` | Local **public** peer material |
| `~/.freeq/peers/received/` | Public peers installed by pair/bootstrap |
| `~/.freeq/pair/` | Invite / guest exchange scratch |

## Fully automated patterns

### A) Gateway leaf (Starlink / CGNAT / site edge) — recommended

**On the gateway host** (after install, identity exists):

```bash
# Serve PUBLIC peer.env only (never private keys)
freeq pair publish --port 8792
# Leaves use: http://GATEWAY_IP:8792/v1/public-peer.env
```

**On each leaf** (one command / cloud-init — no file handoff):

```bash
# During install:
curl -fsSL …/freeq-install-linux.sh | \
  FREEQ_GATEWAY_ENDPOINT=gw.example:51820 \
  FREEQ_GATEWAY_PEER_URL=http://gw.example:8792/v1/public-peer.env \
  FREEQ_REMOTE_OVERLAY=10.66.0.2/32 \
  bash

# Or after install:
FREEQ_GATEWAY_ENDPOINT=gw.example:51820 \
FREEQ_GATEWAY_PEER_URL=http://gw.example:8792/v1/public-peer.env \
FREEQ_REMOTE_OVERLAY=10.66.0.2/32 \
freeq pair bootstrap --auto-start
```

Optional: protect publish with `--code SECRET` and pass the same secret as HTTP Bearer on fetch (still not a private key).

### B) Direct node ↔ node (LAN / one side reachable)

```bash
# Node A
freeq pair host --auto-start
# prints: freeq pair join-host --url http://A_IP:8791 --code … --auto-start

# Node B (paste the one-liner, or inject via env)
FREEQ_PAIR_URL=http://A_IP:8791 FREEQ_PAIR_CODE=… freeq pair bootstrap --auto-start
```

No peer.env files are copied by hand.

### C) API invite (bundle URL + code)

```bash
freeq pair invite --endpoint A_PUBLIC:51820
# publish invite-latest.json to HTTPS if desired
freeq pair join --invite-url https://…/invite.json --code CODE --auto-start
```

## What Cloud adds later

Core automation removes **human file trade**. FreeQ Cloud adds **provisioning, approval, payment, IdP/MDM hooks, fleet rekey, and policy**—same dataplane, stronger control plane.

## Security notes

- Pair codes authorize **public peer exchange**, not bulk tunnel keys.
- Prefer short-lived codes; do not reuse forever.
- Pin gateway peer URLs to HTTPS or a trusted LAN when possible.
- Private keys stay on-box; never publish `identity.key` or private fields.
- Peer key rotation API is still evolving; session crypto is separate from pair codes.

## Commands quick ref

| Command | Use |
|---------|-----|
| `freeq pair show` | Local pair state |
| `freeq pair host --auto-start` | Direct pair host |
| `freeq pair join-host …` | Direct pair guest |
| `freeq pair publish` | HTTP publish public peer.env |
| `freeq pair gateway …` | Leaf → gateway |
| `freeq pair bootstrap` | Env-driven auto pair |
