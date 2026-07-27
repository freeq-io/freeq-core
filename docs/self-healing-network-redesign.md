# FreeQ Self-Healing Network Redesign

Status: architectural mandate for the next gateway/direct rewrite

FreeQ must become a self-healing network, not a collection of scripts that
start a daemon and leave the operator to diagnose the real state. Every direct
and relay decision should be guided by the principles below.

Security is the top objective. Reliability, convenience, and performance are
not allowed to create a path for unauthorized access, metadata leakage, key
exposure, route hijacking, downgrade, replay, or gateway impersonation.

## Product Rule

FreeQ must not report success until the specific user goal is true.

For example:

- "daemon running" means only a process exists
- "gateway connected" means the gateway session is established and healthy
- "relay ready" means both leaves have active sessions and compatible relay
  material
- "leaf-to-leaf working" means a bidirectional probe passed through the selected
  path

Process state is not network health.

## Security-First Invariants

The redesign must preserve these invariants:

- A gateway is used only when one or both leaves cannot accept inbound traffic,
  such as hotel Wi-Fi, airport Wi-Fi, Starlink CGNAT, LTE, enterprise guest
  networks, or other non-dialable networks.
- The gateway must never assume it can call, dial, or open a fresh inbound
  connection to a leaf node. Port forwarding is not available in the relay
  threat model.
- Leaves initiate outbound sessions to the gateway. The gateway forwards only
  across already-authenticated, active leaf sessions.
- The gateway must authenticate leaf identity before accepting traffic from a
  session.
- The gateway must authorize every forwarded destination. It must never act as
  an open proxy, packet reflector, or route amplifier.
- The gateway must not require the end-to-end payload key for leaf-to-leaf
  confidentiality.
- Relay metadata must be minimized, redacted in logs, and retained only for
  operational health, abuse prevention, audit, and support evidence.
- Failure handling must be fail-closed. Ambiguous key, identity, route, or
  session state must stop forwarding rather than guessing.
- Automatic repair must not weaken authentication, skip authorization, expose
  secrets, widen routes, or leave stale privileged state behind.
- Rollback must remove only FreeQ-owned routes, processes, state files, and
  network changes.

## Ten Required Capabilities

1. Gateway reachability

   FreeQ must test whether the gateway is reachable from the current network
   before claiming that gateway mode is available. It should distinguish host
   unreachable, TCP blocked, UDP blocked, DNS failure, authentication failure,
   and timeout.

2. Session establishment

   FreeQ must know whether an authenticated transport session exists, when it
   was established, when it last carried traffic, and why it failed. It must not
   treat a configured peer as an active tunnel.

3. Relay key presence and match proof

   Users must not manually copy environment variables for relay keys. FreeQ must
   provision relay material, store it safely, rotate it, and prove that both
   leaves are using compatible material without exposing secrets in logs or UI.

4. Route installation

   FreeQ must install, verify, and roll back only the routes it owns. It must
   prove that each intended overlay destination resolves to the expected TUN
   interface before moving to the next state.

5. TUN packet observation

   FreeQ must verify that packets actually enter and leave the virtual
   interface. Route presence alone is not enough.

6. Active peer presence

   A relay gateway must track active leaves by authenticated node identity. A
   relay path is not ready until the required leaves are currently attached and
   fresh.

7. Bidirectional probe

   FreeQ must run a safe bidirectional probe and report the result as direct,
   relay, waiting-for-peer, degraded, or failed. One-way success is not enough
   for a healthy tunnel claim.

8. Automatic reconnect and backoff

   FreeQ must repair stale sessions, retry failed sessions with bounded backoff,
   and surface the current retry state. It must not leave dead sessions in the
   active session table.

9. Clear failure state

   Every failure must produce a user-facing state and a support-facing reason.
   Raw pings and logs are evidence, not the product interface.

10. Full rollback

   FreeQ must return the machine to normal networking. Stop and failure paths
   must remove FreeQ-owned routes, stop FreeQ-owned daemons, renew networking
   when requested, and avoid damaging unrelated user network state.

## Required State Model

The replacement network manager should expose states like these:

- `IDLE`
- `CHECKING_GATEWAY_REACHABILITY`
- `GATEWAY_UNREACHABLE`
- `LOCAL_NETWORK_BLOCKING_UDP`
- `AUTHENTICATING_GATEWAY`
- `GATEWAY_SESSION_ESTABLISHED`
- `ROUTES_INSTALLED`
- `TUN_OBSERVING_PACKETS`
- `WAITING_FOR_REMOTE_LEAF`
- `RELAY_KEY_MISSING`
- `RELAY_KEY_MISMATCH_SUSPECTED`
- `RELAY_READY`
- `DIRECT_READY`
- `BIDIRECTIONAL_PROBE_PASS`
- `BIDIRECTIONAL_PROBE_FAIL`
- `ROLLING_BACK`
- `ROLLED_BACK`

The CLI, API, and local web UI should all read from the same state machine.

## Direct And Relay Are Separate Lanes

Direct mode and relay mode must be separate paths in config, code, tests, and
UX.

Direct mode:

- preferred when nodes can reach each other directly
- no gateway in the data path
- Cloud may observe and audit but must not be required

Relay mode:

- used when direct reachability is blocked
- leaves connect outbound to a gateway
- gateway forwards only between authenticated active leaf sessions
- gateway must not need the end-to-end payload key
- gateway never dials a non-dialable leaf as a fallback

## No Manual Secret Rituals

The replacement flow must not require operators to paste relay keys into shell
environment variables. A safe bootstrap path may use an invite or enrollment
bundle, but the product must own:

- generation
- storage
- validation
- rotation
- revocation
- redaction

## Acceptance Gates

The redesigned gateway/direct system is not supported until these pass:

- clean install on a fresh Mac
- clean rollback to normal networking
- direct path success when direct connectivity is available
- relay path success with both leaves behind non-dialable networks
- tests prove the gateway never dials a leaf in relay mode
- tests prove the gateway cannot be used as an open proxy or reflector
- tests prove unauthorized destinations are rejected fail-closed
- blocked gateway network produces `GATEWAY_UNREACHABLE` or
  `LOCAL_NETWORK_BLOCKING_UDP`
- missing remote leaf produces `WAITING_FOR_REMOTE_LEAF`
- relay-key mismatch produces `RELAY_KEY_MISMATCH_SUSPECTED` without exposing
  key material
- stale sessions self-repair without manual restart
- local web UI and CLI report the same state
- support bundle captures enough evidence for diagnosis without secrets

## Development Guidance

Any future gateway, relay, setup, status, doctor, UI, or Cloud provisioning work
must be judged against this document. If a change makes the operator run raw
ping commands, manually paste keys, inspect route tables, or infer health from
"daemon running," it is the wrong shape.
