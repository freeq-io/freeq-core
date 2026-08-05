# FreeQ Direct and Gateway Relay Architecture

Status: legacy design baseline and learning artifact

This document preserves the first direct/relay lane split and field-test
lessons. It is not the target product workflow. The next implementation must be
guided by the self-healing network redesign in
[`docs/self-healing-network-redesign.md`](self-healing-network-redesign.md).

Current field tests use the hardened accept-only gateway binary on AWS:

```text
systemd service: freeq-gateway.service
public listen:   UDP 51820
local status:    http://127.0.0.1:6790/status
legacy daemon:   freeqd.service should remain stopped for this path
```

Leaf Macs still run `freeqd` locally and expose their local API at
`http://127.0.0.1:6789/v1/status`.

The legacy AWS gateway path proved that relay is technically possible, but it
also proved that a manual gateway flow is too fragile for users. Do not build
new user-facing behavior around manual relay keys, manual extra routes, raw
ping interpretation, or "daemon running" as a success state.

FreeQ has two separate connectivity lanes. They must not be blended in code,
documentation, setup scripts, or product language.

## Lane 1: Direct Peer Connection

Use direct mode when two trusted nodes can reach each other over UDP.

```text
node A <================ FreeQ direct tunnel ================> node B
```

Direct mode properties:

- each node may dial the other node's reachable endpoint
- no gateway is required for the data path
- FreeQ Cloud may observe, provision, audit, and report the direct tunnel, but
  the tunnel must not depend on Cloud
- this is preferred when both sides have real reachability

Direct mode is appropriate for public servers, private networks with routing,
lab environments, site-to-site links, and any pair where inbound reachability is
known to work.

## Lane 2: Gateway Relay For NAT/CGNAT Nodes

Use gateway relay mode when one or both leaf nodes cannot accept inbound
traffic. Common examples include Starlink residential, LTE, hotels, airports,
coffee shops, enterprise guest Wi-Fi, and carrier-grade NAT.

```text
Patrick leaf  --outbound only-->  public gateway  <--outbound only--  David leaf
```

Gateway relay properties:

- each leaf establishes and maintains an outbound session to the public gateway
- the gateway accepts leaf sessions
- the gateway must never dial back into a leaf node in relay mode
- leaf public endpoints behind CGNAT are not reliable routing targets
- the gateway routes packets only across authenticated, active leaf sessions

The gateway is a rendezvous relay for the data plane, not a fallback direct
dialer. If a design expects the gateway to call a leaf behind hotel Wi-Fi,
Starlink CGNAT, LTE, airport Wi-Fi, or a guest network, that design is wrong.

## Required Gateway Session Table

The gateway must maintain a table keyed by authenticated node identity:

```text
patrick-mac          -> active inbound session from Patrick
davids-macbook-pro  -> active inbound session from David
```

When Patrick sends a packet to David:

```text
1. Patrick routes 10.66.0.165 to the gateway session.
2. Gateway authenticates the source session as patrick-mac.
3. Gateway resolves destination 10.66.0.165 -> davids-macbook-pro.
4. Gateway forwards over David's existing inbound session.
5. David writes the packet to its local TUN interface.
```

When David replies, the same process runs in reverse.

The gateway must not treat `davids-macbook-pro` as a dialable public endpoint in
gateway relay mode. If David has no active inbound session, the correct result
is:

```text
remote leaf offline: no active inbound session for davids-macbook-pro
```

not:

```text
attempting outbound connection to davids-public-ip:51820
```

## Rendezvous Metadata vs Relay Data Plane

Rendezvous metadata helps nodes discover whether direct connectivity is likely.
Relay data plane forwards packets when direct connectivity is not viable.

```text
rendezvous metadata:  "can these two nodes try direct?"
relay data plane:     "carry packets through a gateway"
```

FreeQ Cloud may provide rendezvous metadata, reachability tests, direct-path
awareness, and relay provisioning. FreeQ Core must enforce the actual data-plane
behavior.

## Gateway Routing Envelope

For opaque end-to-end payloads, the gateway still needs enough authenticated
routing metadata to forward packets without reading the inner payload.

The long-term packet shape should be:

```text
outer FreeQ transport: leaf <-> gateway
routing envelope:      destination node id or overlay IP
inner payload:         end-to-end encrypted leaf <-> leaf packet
```

This lets the gateway:

- authenticate the source leaf
- route to the destination leaf
- avoid reading leaf-to-leaf payload data
- record operational evidence without logging packet contents

## FreeQ Cloud Awareness

FreeQ Cloud must understand both lanes:

- direct tunnel active: no relay required
- relay tunnel active: gateway is carrying data between leaf sessions
- direct attempt failed: relay is required or recommended
- remote leaf offline: no active gateway session

This matters for provisioning, security auditing, local SLM analysis, scan
evidence, sniffing/traffic observation, SOC alerts, and customer-facing reports.

Cloud should know that a direct connection exists, but it should not force that
direct connection through a gateway. Conversely, Cloud should know when direct
connectivity is impossible and provision or recommend a relay gateway.

## Implementation Guardrails

Do not implement gateway relay by dialing CGNAT leaves from the gateway.

Do implement:

- explicit peer connectivity mode in config
- `direct` peers as dialable when configured
- `gateway_client` peers as outbound-only to a gateway
- `relay_leaf` peers on a gateway as accept-only
- active session routing on the gateway
- clear API state for direct, relay, offline, and failed-direct cases
- tests where leaf public endpoints are intentionally unreachable

The acceptance test for gateway relay is:

```text
Patrick behind unknown network -> AWS gateway <- David behind Starlink/CGNAT
```

Both leaves must connect outbound to the gateway, and leaf-to-leaf packets must
flow without the gateway dialing either leaf.
