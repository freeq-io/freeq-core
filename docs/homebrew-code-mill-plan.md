# FreeQ Homebrew Code Mill Plan

Goal: make FreeQ feel like a normal Homebrew-managed Mac tool.

Formal strategy: `docs/homebrew-install-maintenance-strategy.md`.

Primary user contract:

```bash
brew install freeq
brew upgrade freeq
freeq setup
freeq gateway
freeq stop
```

## Code Mill Stripes

1. Formula release source
   - Move from branch-based alpha formula to tagged release tarball.
   - Acceptance: formula has stable `url`, `sha256`, `license`, and `head`.

2. Tap repository
   - Create `freeq-io/homebrew-tap` with `Formula/freeq.rb`.
   - Acceptance: `brew install freeq-io/tap/freeq` works from a clean Mac.

3. Bottle workflow
   - Add release workflow to build Apple Silicon and Intel bottles.
   - Acceptance: `brew install freeq-io/tap/freeq` pours a bottle when available.

4. CLI lifecycle polish
   - Keep `freeq setup`, `freeq gateway`, `freeq stop`, and `freeq status`
     consistent with Homebrew install/upgrade ownership.
   - Acceptance: no docs recommend `freeq --install` or raw `sudo kill`.

5. Rollback verification
   - Add host-level macOS rollback smoke test for stale routes and DHCP mode.
   - Acceptance: start/stop leaves no FreeQ-owned host route behind.

6. Brew services decision
   - Decide whether `freeqd` should use `brew services` for long-running mode or
     remain script-started during alpha.
   - Acceptance: docs state one supported service model.

7. Gateway onboarding
   - Package a gateway peer-file flow that does not require hidden-folder access.
   - Acceptance: user can place gateway file in `~/FreeQ/02-put-peer-file-here`
     and run `freeq gateway`.

8. Doctor command
   - Add `freeq doctor` for route, DHCP, daemon, setup folder, and peer-file
     diagnostics.
   - Acceptance: doctor prints PASS/FAIL with one next action per failure.
