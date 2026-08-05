# SOC 2 Readiness Audit Findings - 2026-08-04

Status: internal readiness review, not a CPA attestation.

FreeQ has not completed an independent SOC 2 examination. This document
memorializes an internal repository-level readiness review performed against
the current `freeq-core` repo. It is intended to become a living evidence and
remediation tracker before any formal SOC 2 Type I or Type II engagement.

## Scope

Reviewed surfaces:

- source repository governance and change-management evidence
- CI, pre-commit, and security test evidence
- local API and gateway management surfaces
- crypto/auth design documentation and implementation guardrails
- Linux/systemd deployment hardening artifacts
- legacy/demo deployment artifacts that could confuse production scope

SOC 2 reference frame:

- Security is the required Trust Services Criteria category.
- Availability, Processing Integrity, Confidentiality, and Privacy should be
  scoped only when FreeQ makes customer commitments in those areas.
- This review focuses on repo evidence likely to support Security, Availability,
  and Confidentiality readiness.

## Executive Summary

FreeQ has strong engineering security evidence for an alpha project: explicit
threat modeling, crypto design notes, CI, pre-commit checks, private-key file
permission checks, local API loopback enforcement, status redaction, security
audit tests, and hardened Linux systemd templates.

The repo is not SOC 2 ready yet. The highest-priority gaps are repository
governance controls outside normal code review, stale unauthenticated demo
gateway artifacts, incomplete local API authorization, and missing release
provenance/SBOM/signing evidence.

## High-Risk Findings

### 1. Main Branch Is Not Protected

Finding:

The GitHub API reported that `main` is not branch-protected. Dependabot security
updates, GitHub secret scanning, non-provider secret scanning, push protection,
and validity checks were also reported disabled.

Audit impact:

This is a change-management and vulnerability-management design gap. Existing
CI is useful evidence, but SOC 2 auditors generally expect controls that prevent
unreviewed or untested changes from entering the default branch.

Evidence:

- `.github/workflows/ci.yml` runs fmt, check, clippy, tests, macOS tests, MSRV,
  and `cargo audit`.
- `.github/CODEOWNERS` routes default and crypto/auth review ownership.
- CODEOWNERS alone does not enforce approval count or passing checks.

Recommended remediation:

- Enable branch protection for `main`.
- Require pull requests, CODEOWNERS review, and passing CI.
- Require two approvals for crypto/auth paths if that remains the stated policy.
- Disable force-push and branch deletion.
- Enable Dependabot security updates.
- Enable GitHub secret scanning and push protection.
- Consider signed commits or signed tags for release branches.

### 2. Legacy Flask Gateway Remains Deployable

Finding:

`gateway.py`, `Dockerfile`, and `docker-compose.yml` remain in the repo as a
deployable Flask gateway on `0.0.0.0:8080`. The mock gateway exposes `/risk`
and `/ota` without authentication and logs submitted request data.

Audit impact:

This creates production-scope ambiguity. Even if intended as an old proof of
concept, an auditor or customer could reasonably treat a deployable gateway
artifact as part of the system unless it is removed, quarantined, or clearly
excluded.

Evidence:

- `gateway.py`
- `Dockerfile`
- `docker-compose.yml`

Recommended remediation:

- Delete the legacy Flask gateway if no longer needed.
- Or move it under `examples/insecure-demo/` with an explicit warning banner.
- Add CI/release guardrails to ensure it is not packaged or deployed.
- Prefer the Rust `freeq-gateway` binary as the only production gateway path.

### 3. Local API Authorization Is Header-Based, Not Secret-Based

Finding:

Mutating local API routes require `x-freeq-setup-intent: local-dashboard`, but
this is a static browser-intent header, not a per-install secret, OS auth check,
or cryptographically strong management token.

Audit impact:

The current design is acceptable only if the local API is strictly loopback-only
and scoped as alpha local setup UX. It is not sufficient evidence for a
production management API authorization control.

Evidence:

- `crates/freeq-api/src/router.rs` protects mutating routes with
  `require_setup_intent`.
- `crates/freeq-config/src/lib.rs` rejects non-loopback API binds by default
  unless `node.allow_unsafe_api_bind` is explicitly true.

Recommended remediation:

- Add a generated per-install setup token or OS-local authorization check.
- Store the token outside browser storage.
- Continue requiring loopback bind by default.
- Fail closed if unsafe non-loopback API binding is requested without stronger
  authentication.

## Medium-Risk Findings

### 4. No Independent Cryptographic Audit Yet

Finding:

`SECURITY.md` correctly states that FreeQ has not received an independent
cryptographic audit.

Audit impact:

This is transparent and appropriate for alpha, but customers and auditors will
ask how cryptographic design risk is independently reviewed.

Evidence:

- `SECURITY.md`
- `docs/threat-model.md`
- `docs/crypto-design.md`
- `docs/engineering-hardening-log.md`

Recommended remediation:

- Keep the alpha warning until an external audit completes.
- Track an external crypto review plan, target firm, scope, and remediation SLA.
- Link audit report summaries and remediation status once available.

### 5. Some Management Controls Are Scaffolded but Not Implemented

Finding:

Some local API/CLI controls return not implemented, including peer removal,
API-level peer key rotation, and algorithm switching.

Audit impact:

This is not a finding if product docs make no production commitment. It becomes
a SOC 2 exception if those capabilities are represented as available controls.

Evidence:

- `crates/freeq-api/src/handlers/peers.rs`
- `crates/freeq-api/src/handlers/algorithm.rs`
- `cli/src/main.rs`

Recommended remediation:

- Ensure docs and UI label these controls as alpha/scaffolded until complete.
- Either implement or remove exposed mutating routes before production scope.
- Add tests for each implemented management control and its authorization path.

### 6. Release Provenance and Artifact Controls Are Thin

Finding:

CI and pre-commit checks are strong, but the repo does not currently show a
formal release workflow with SBOM generation, signed checksums, artifact
attestation, SLSA provenance, or release approval gates.

Audit impact:

This affects supply-chain, change-management, and deployment evidence.

Evidence:

- `.github/workflows/ci.yml`
- `scripts/git-pre-commit.sh`
- no observed release provenance or SBOM workflow

Recommended remediation:

- Add a release workflow that builds pinned targets.
- Generate SBOMs for release artifacts.
- Sign release artifacts or checksums.
- Publish provenance/attestation.
- Require release approval separate from normal merge approval.

## Positive Control Evidence

The following controls are good foundations for SOC 2 readiness:

- CI runs formatting, compile checks, clippy, tests, macOS tests, MSRV checks,
  and dependency audit.
- Pre-commit guard runs setup flow, Linux deployment harness, clippy, and
  high-severity security tests.
- Crypto/auth crates forbid unsafe code and deny risky lint classes.
- Local API non-loopback bind is rejected by default.
- Status errors are redacted before API exposure.
- Gateway status HTTP must bind to loopback.
- Identity private-key files are checked for owner-only permissions before load;
  generated keys are written `0600`.
- Linux/systemd deployment template uses a dedicated service user, bounded
  capabilities, `NoNewPrivileges`, strict filesystem protection, restricted
  address families, and scoped TUN device access.
- The gateway relay design preserves the invariant that the gateway accepts
  leaf sessions and never dials leaves.
- Threat model and engineering hardening docs explicitly track known alpha gaps.

## Recommended Remediation Order

1. Enable GitHub branch protection and repository security features.
2. Remove or quarantine the legacy Flask gateway artifacts.
3. Add real local setup authorization beyond a static header.
4. Add release SBOM, signing, checksums, and provenance.
5. Implement or hide scaffolded API/CLI management controls.
6. Create a SOC 2 control matrix that maps evidence to CC1-CC9.
7. Add incident-response, vulnerability-management, access-review, vendor-risk,
   backup/restore, and availability runbooks outside source code.
8. Schedule an independent cryptographic/security review and track remediation.

## Suggested Control Matrix Seeds

Use this initial mapping to build a formal readiness matrix:

| SOC 2 theme | Existing evidence | Gap |
| --- | --- | --- |
| Change management | CI, CODEOWNERS, pre-commit guard | Branch protection not enabled |
| Vulnerability management | `cargo audit` in CI | Dependabot and GitHub secret scanning disabled |
| Logical access | Loopback API bind, setup-intent header | No per-install management token |
| Confidentiality | Hybrid PQC design, status redaction, key permissions | No independent crypto audit yet |
| Availability | Gateway self-healing status, systemd restart policy | Formal uptime/DR runbooks not present |
| Deployment security | Hardened Ansible systemd template | Release provenance/SBOM/signing not present |
| Incident response | `SECURITY.md` reporting process | Internal IR runbook and evidence workflow not present |

## Disposition

Current readiness: alpha security foundation with meaningful controls, not yet
SOC 2 ready.

Target near-term state: SOC 2 Type I readiness for Security only after repo
governance, release provenance, API authorization, and stale artifact cleanup
are complete.

Target later state: SOC 2 Type II readiness after controls operate consistently
over an observation period and evidence collection is routine.
