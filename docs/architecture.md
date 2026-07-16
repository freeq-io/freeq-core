# FreeQ Architecture

## System Layer Diagram

```
┌─────────────────────────────────────────────────────────┐
│  APPLICATION LAYER — your services, APIs, microservices  │
├─────────────────────────────────────────────────────────┤
│  FREEQ CLOUD (paid) — Fleet Dashboard · Scanner · NMS   │
│                        SIEM/SOAR · ITSM · Provisioning  │
├─────────────────────────────────────────────────────────┤
│  FREEQ CORE DAEMON (AGPL v3)                            │
│  ┌──────────────────┐  ┌──────────────────────────────┐ │
│  │  Control Plane   │  │       Data Plane             │ │
│  │  freeq-config    │  │  freeq-crypto                │ │
│  │  freeq-auth      │  │  freeq-transport (QUIC)      │ │
│  │  freeq-api       │  │  freeq-tunnel (TUN/TAP)      │ │
│  └──────────────────┘  └──────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│  CRYPTO — FIPS 203 ML-KEM · FIPS 204 ML-DSA · X25519   │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT — QUIC (RFC 9000) · UDP · io_uring (Linux)   │
├─────────────────────────────────────────────────────────┤
│  OS — Linux TUN/TAP · macOS utun · Windows WinTUN       │
└─────────────────────────────────────────────────────────┘
```

## Product Doctrine: Core Cloaks, Cloud Manages

FreeQ Core must be independently useful. A self-managed operator should be able
to install FreeQ Core, bootstrap trust with a simple local artifact, start a
node, and establish a protected direct tunnel without depending on a hosted
control plane.

FreeQ Cloud exists to replace the ugly parts of self-management with a polished
management plane:

- enrollment instead of manual peer-file exchange
- pending-peer approval and revocation workflows
- fleet posture, cloaking status, tunnel health, and key-rotation visibility
- local evidence collection through `freeq-api`
- SOC, ITSM, CMDB, NMS, and provisioning integrations
- rendezvous and optional relay for enterprise network realities

This is the intended product promise:

```text
FreeQ Core:  cloak for nothing, self-manage if you want.
FreeQ Cloud: upgrade the plane for enrollment, observability, workflow, and scale.
```

Cloud may make FreeQ easier to operate, but it must not become mandatory for
the direct-node security claim.

## Hybrid KEM Handshake

| Step | Party    | Action |
|------|----------|--------|
| 1    | A → B    | Send ML-DSA-65 signature over `(nonce ∥ A_kem_pubkey)` |
| 2    | B        | Verify A's signature against registered public key |
| 3    | B → A    | Return ML-DSA-65 signature over `(nonce ∥ A_nonce ∥ B_kem_pubkey)` |
| 4    | A        | Verify B's signature — mutual authentication complete |
| 5    | A → B    | ML-KEM-768 encapsulation: generate shared secret + ciphertext |
| 6    | Both     | X25519 ECDH key exchange in parallel with step 5 |
| 7    | Both     | `session_key = HKDF-SHA256(kem_secret ∥ ecdh_secret, nonce, info)` |
| 8    | Both     | Derive post-handshake rekey seed and role-specific traffic keys |
| 9    | Both     | Exchange and verify key-confirmation proofs |
| 10   | Both     | AES-256-GCM bulk encryption begins. Ephemeral keys zeroized. |

## Crate Dependency Graph

```
freeqd (daemon binary)
├── freeq-crypto     (no internal deps)
├── freeq-config     (no internal deps)
├── freeq-transport  → freeq-crypto
├── freeq-auth       → freeq-crypto, freeq-config
├── freeq-tunnel     → freeq-crypto, freeq-transport, freeq-auth, freeq-config
└── freeq-api        → freeq-config, freeq-auth

freeq (CLI binary)
├── freeq-config
└── freeq-api
```

## Security Operations Integration Boundary

FreeQ Core exposes node-local status, metrics, tunnel state, and future
management operations through `freeq-api`. It should not contain
vendor-specific SIEM, SOAR, ITSM, or provisioning connectors.

The planned integration boundary is:

```text
freeqd
└── freeq-api (local only)
    └── freeq-agent
        └── FreeQ Cloud backend
            └── Event export pipeline
                ├── JSON webhooks
                ├── syslog / CEF
                ├── Splunk HEC
                ├── Microsoft Sentinel / Log Analytics
                ├── Elastic / OpenSearch
                ├── QRadar / SOAR adapters
                ├── ServiceNow / Jira / CMDB adapters
                └── Ansible / Terraform / gateway provisioning hooks
```

This keeps the daemon focused on cryptographic overlay protection while FreeQ
Cloud handles aggregation, event normalization, delivery retries, tenant export
configuration, ticketing workflows, provisioning orchestration, validation
evidence, and vendor-specific integration formats.

The operating principle for this boundary is documented in
`docs/enterprise-telemetry-cloud-path.md`: FreeQ Core must disappear on the
wire and emit local evidence; FreeQ Cloud manages fleet-scale correlation,
workflow, integrations, rendezvous, and optional relay services.

The intended Cloud workflow is closed-loop remediation:

```text
scanner finding
    -> SOC alert
        -> ticket or change request
            -> approved gateway or policy deployment
                -> validation through freeq-agent and freeq-api
                    -> evidence attached back to the ticket
```
