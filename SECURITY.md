# Security Policy

## Audit Status

FreeQ has **not yet received an independent cryptographic audit**. Treat FreeQ
as alpha/beta software — do not use it to protect classified or life-safety
data.

For protocol design assumptions, see [`docs/threat-model.md`](docs/threat-model.md)
and [`docs/crypto-design.md`](docs/crypto-design.md).

## Reporting Vulnerabilities

Email **security@getfreeq.com** with a clear report (PGP optional if published on
the FreeQ website).

We aim to:
1. Acknowledge receipt within 48 hours
2. Provide a fix timeline within 7 days
3. Coordinate disclosure after a fix is available

Responsible reporters are credited unless they prefer anonymity.

## Scope

In scope: `freeq-crypto`, `freeq-auth`, `freeq-transport`, `freeq-tunnel`,
gateway relay behavior, and the handshake protocol.

Out of scope: denial-of-service via resource exhaustion, issues in upstream
crates (report to those projects directly).
