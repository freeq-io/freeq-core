# Security Policy

## Audit Status

FreeQ has **not yet received an independent cryptographic audit**. We are fundraising for an NCC Group or Cure53 engagement. Until then, treat FreeQ as beta software — do not use it to protect classified or life-safety data.

## Reporting Vulnerabilities

Email **security@getfreeq.io** with a PGP-encrypted report. Our public key is published at `getfreeq.io/security-pgp.asc`.

We observe a **90-day disclosure window**. We will:
1. Acknowledge receipt within 48 hours
2. Provide a fix timeline within 7 days
3. Issue a CVE and publish a post-mortem after the fix is deployed

Responsible reporters are credited in our Hall of Fame unless they prefer anonymity.

## Scope

In scope: `freeq-crypto`, `freeq-auth`, `freeq-transport`, `freeq-tunnel`, and the handshake protocol.

Out of scope: denial-of-service via resource exhaustion, issues in upstream crates (report to RustCrypto / quinn directly).
