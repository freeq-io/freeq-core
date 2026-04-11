# Contributing to FreeQ Core

## Contributor License Agreement

**All contributions require a signed CLA before your PR can be merged.**

We use [CLA Assistant](https://cla-assistant.io/) — signing is automated on PR submission. Individual and corporate CLAs are both available.

Without a CLA, we cannot commercialize, relicense, or sell FreeQ. This protects the project's future.

## Code Review Requirements

- All PRs require at least one maintainer approval.
- Changes to `freeq-crypto`, `freeq-auth`, or the handshake protocol require **two maintainer approvals**.
- CI must be green (tests, `cargo clippy`, `cargo fmt`).

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(crypto): implement ML-KEM-768 encapsulation
fix(auth): prevent timing leak in signature verification
docs(readme): add quick start guide
```

## Good First Issues

Look for issues tagged `good first issue` on GitHub. The docs, config parsing, and CLI display are great starting points that don't touch the crypto layer.

## Security-Sensitive Changes

Do not open public PRs for security vulnerabilities. Email security@freeq.io first. See [SECURITY.md](SECURITY.md).
