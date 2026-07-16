# FreeQ Core And Cloud Enterprise Path

## Principle

FreeQ Core must be able to make the direct-node security claim without FreeQ
Cloud. A node should disappear on the wire, protect traffic with the local
post-quantum tunnel, and emit local evidence that the enterprise can collect
through controlled channels.

FreeQ Cloud should make that posture easier to operate at fleet scale. It
should manage policy, correlation, workflow, integrations, reporting,
rendezvous, and optional relay services, but it must not be required for the
open-source core to be truly cloaked.

## Commercial Shape

The FreeQ product line should be advertised as a clean upgrade path:

```text
Start with FreeQ Core:
  self-managed, inspectable, open-source, direct-node protection.

Upgrade to FreeQ Cloud:
  enrollment, approval, observability, compliance evidence, integrations,
  rendezvous, optional relay, and fleet operations.
```

The peer file is the current poor-man's trust bootstrap in Core. It should be
treated as an honest local provisioning artifact, not as the final user
experience. FreeQ Cloud replaces that rough edge with managed enrollment and
approval while preserving the same security boundary: no peer is trusted until
its identity, route authority, and policy are approved.

## Boundary

| Layer | Responsibility | Non-goal |
|-------|----------------|----------|
| FreeQ Core | No network-visible response to unauthenticated probes, PQ tunnel establishment, local-only status, local telemetry, probe-drop counters, tunnel state | Vendor-specific SIEM, SOAR, ITSM, provisioning, or hosted control-plane dependency |
| FreeQ Agent | Poll local `freeq-api`, normalize node evidence, batch and forward approved telemetry, receive approved management intents | Directly bypassing local policy or writing secrets into cloud systems |
| FreeQ Cloud | Fleet inventory, policy orchestration, alert correlation, ticketing, compliance evidence, customer-approved AI analysis, rendezvous and optional relay | Becoming mandatory for the direct-node security claim |
| Enterprise Tools | SIEM, SOAR, ITSM, CMDB, NMS, EDR/NDR, provisioning systems | Receiving packet payloads, tunnel plaintext, private keys, or session secrets |

## Silent On Wire, Signal Inside

Strict cloaking means the unauthenticated external party receives no useful
network response. It does not mean the enterprise is blind.

FreeQ Core should record local, rate-limited telemetry for unauthenticated
probes:

- timestamp bucket
- source address and port when policy allows
- local listener address
- reason class, such as `malformed_udp`, `generic_quic_initial`,
  `unknown_peer`, `bad_signature`, `replay`, or `rate_limited`
- counters for dropped probes, admitted first datagrams, replay drops, and
  malformed drops
- sampling metadata that avoids packet payload capture by default

This telemetry must stay out-of-band. The probe receives silence; the
enterprise receives evidence through local logs, `freeq-api`, syslog/CEF,
OpenTelemetry, SIEM export, or FreeQ Cloud agent forwarding.

## Core Hardening Path

1. Add a pre-QUIC UDP admission gate so random UDP and generic QUIC probes are
   dropped before Quinn can respond.
2. Make strict cloaking the default node posture.
3. Add first-datagram authentication, replay protection, and bounded timestamp
   or nonce windows without weakening ML-DSA identity or ML-KEM/X25519 session
   key confirmation.
4. Add local probe telemetry and counters with rate limits and payload-safe
   event classes.
5. Expose local-only status through `freeq-api`, including cloaking mode,
   admission state, and drop counters.
6. Prove the posture with loopback and host-level tests:
   random UDP gets no response, generic QUIC gets no response, valid FreeQ
   peers still connect.

## Cloud Enterprise Path

1. Define `freeq.event.v1` for node status, tunnel state, cloaking probe
   telemetry, scan findings, ticket state, remediation state, and validation
   evidence.
2. Build connector-safe exports first:
   JSON webhook, syslog/CEF, Splunk HEC, Microsoft Sentinel, Elastic/OpenSearch,
   QRadar, SOAR webhook, ServiceNow, Jira, CMDB, Ansible, Terraform, and
   cloud-init intent artifacts.
3. Preserve duplicate control and approval boundaries. Cloud may propose or
   request remediation; production changes require explicit approved workflow.
4. Add fleet posture views:
   cloaking status, probe trends, tunnel health, key-rotation state, policy
   drift, gateway placement, and validation evidence.
5. Support deployment modes:
   direct node-to-node, customer-hosted gateway, cloud rendezvous, and optional
   relay. Cloud rendezvous and relay are enterprise convenience features, not
   prerequisites for Core security.
6. Keep customer-sensitive analysis local by default for regulated
   environments. Cloud AI is opt-in; local/private analysis records must include
   model version, prompt version, evidence IDs, policy pack, and human review
   disposition.

## Enterprise Acceptance Criteria

- An unauthenticated internet scanner receives no FreeQ response.
- Enterprise telemetry records that a probe happened, without packet payloads
  or secrets.
- A valid registered peer can still establish a tunnel through strict cloaking.
- A Cloud-managed fleet can show which nodes are strictly cloaked, which nodes
  saw probes, which tunnels are healthy, and which remediation workflows are
  open.
- Cloud workflows can create alerts, tickets, and provisioning intents without
  bypassing local approval policy.
- FreeQ Core remains independently useful when Cloud is absent or unreachable.
