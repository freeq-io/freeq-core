# FreeQ Homebrew Install And Maintenance Strategy

Overall framework: `docs/platform-installation-framework.md`.

## Decision

FreeQ should standardize workstation install, update, gateway connection,
rollback, and normal network restoration around Homebrew on every supported
Homebrew target, including macOS and Linux.

The target user contract is:

```bash
brew install freeq
brew upgrade freeq
freeq setup
freeq gateway
freeq stop
freeq status
```

During alpha, the practical public path is expected to be:

```bash
brew install freeq-io/tap/freeq
brew upgrade freeq-io/tap/freeq
```

After the package is stable enough for Homebrew review, FreeQ should submit the
formula to Homebrew core so the user-facing command can become:

```bash
brew install freeq
brew upgrade freeq
```

## Why Homebrew Is The Best Primary Workstation Path

Homebrew is the right default for FreeQ on supported workstation targets because
it gives users a familiar lifecycle without asking them to learn a custom
installer:

- `brew install` owns first install.
- `brew upgrade` owns updates.
- `brew uninstall` owns removal.
- Formula caveats can show the next FreeQ commands at install time.
- CLI binaries, daemon binaries, scripts, and docs can ship together.
- FreeQ avoids building a custom updater that competes with the package
  manager.
- Developers and early testers can use the same model that later customers use.

For a networking tool, this matters. The install path should feel boring,
reversible, and inspectable. FreeQ can ask for privileges when it changes local
networking, but the package lifecycle itself should stay inside a trusted,
standard tool. The command contract should be the same on macOS and Linux even
when the platform-specific rollback implementation differs.

## Tap First, Core Later

A Homebrew tap is a Git repository owned by FreeQ, conventionally named
`homebrew-tap`, that contains the FreeQ formula. A tap does not push anything
into Homebrew core automatically.

Recommended progression:

1. Keep an alpha formula in `freeq-core` for local testing.
2. Create `freeq-io/homebrew-tap`.
3. Publish `Formula/freeq.rb` in that tap.
4. Cut a tagged FreeQ release.
5. Update the formula from a branch source to a tagged release tarball with a
   `sha256`.
6. Validate with:

```bash
brew install --build-from-source freeq-io/tap/freeq
brew test freeq-io/tap/freeq
brew audit --new --formula freeq
```

7. Add bottles for Apple Silicon and Intel Macs.
8. Use Patrick and David as early testers on clean machines and real captive
   Wi-Fi networks.
9. Submit a Homebrew core pull request when the formula, release cadence,
   licensing, tests, and user contract are stable.

Homebrew core acceptance is a review process. Until accepted, `brew install
freeq-io/tap/freeq` is the right public command. After acceptance, `brew install
freeq` becomes the simple command.

## FreeQ Command Ownership

The Homebrew package should install a single primary CLI named `freeq`.

FreeQ Core owns the local endpoint lifecycle:

- `freeq setup` prepares the Mac and local FreeQ setup folder.
- `freeq gateway` connects using the gateway or peer material placed in the
  visible setup folder.
- `freeq stop` stops FreeQ and rolls networking back to the pre-FreeQ state.
- `freeq status` reports daemon, route, peer, and local setup health.

FreeQ Cloud should align with the same command vocabulary. Cloud can own
managed gateway enrollment, relay/rendezvous configuration, enterprise release
coordination, and cloud-side operational guidance, but it should not create a
second competing workstation install experience.

## Network Rollback Requirement

FreeQ must leave basic networking in the same state it found it.

`freeq stop` is the supported rollback command. It must:

- Stop only the FreeQ daemon it owns.
- Remove only FreeQ-owned host routes.
- Restore platform network settings when FreeQ recorded them as the original
  state.
- Renew DHCP or restart the appropriate network manager path when needed after
  captive portal or gateway testing.
- Remove stale rollback state only after cleanup succeeds.
- Report success or failure clearly.

Documentation should not tell normal users to run raw `sudo kill`, edit hidden
files, or manually delete routes. Those commands can remain diagnostic tools
for engineers, but not the product path.

## Other Installer Paths

Homebrew should be the primary workstation path for supported macOS and Linux
targets, but not the only packaging option forever.

Shell installer:

- Useful for development, emergency rollback testing, and legacy bootstrap.
- Should not be the long-term primary user path.
- Should not self-update a Homebrew-managed install.

`.pkg` installer:

- Better if FreeQ later needs a signed enterprise installer, launch daemon
  registration, MDM deployment, or deeper macOS system integration.
- More operational burden than Homebrew and less natural for developer alpha.

Homebrew cask:

- Better if FreeQ ships a native `.app` bundle or GUI package.
- Not necessary for the current CLI and daemon package.

MDM, Jamf, or Intune:

- Appropriate for enterprise rollout.
- Can wrap either the Homebrew formula or a signed `.pkg`.
- Should preserve the same `freeq setup`, `freeq gateway`, and `freeq stop`
  contract.

Linux packages:

- `apt`, `yum`, `dnf`, `apk`, and Nix can be added later for distro-native
  enterprise fleets or environments where Homebrew is not acceptable.
- They should follow the same lifecycle semantics as the Homebrew package where
  possible.
- They should not create different user-facing commands for setup, gateway
  connection, rollback, or status.

Container images:

- Useful for cloud gateway, relay, scanner, and control-plane services.
- Not a replacement for the endpoint workstation install experience.

## Acceptance Criteria

The Homebrew path is ready for broad alpha when:

- `brew install freeq-io/tap/freeq` works on a clean Apple Silicon Mac.
- `brew install freeq-io/tap/freeq` works on a clean Intel Mac.
- `brew install freeq-io/tap/freeq` works on a clean supported Linux target.
- `freeq setup` completes without requiring hidden-folder access.
- `freeq gateway` connects using visible gateway material.
- `freeq stop` removes FreeQ-owned routes and restores normal networking on
  each supported platform.
- Captive Wi-Fi recovery or the platform-equivalent gateway recovery path is
  tested after `freeq stop`.
- `brew upgrade freeq-io/tap/freeq` updates binaries, scripts, and docs.
- `brew uninstall freeq-io/tap/freeq` removes the package-owned files.
- The formula uses a stable tagged release URL and `sha256`.
- `brew test` and `brew audit --new --formula` pass.
- The docs do not present custom curl install as the preferred workstation path.

The Homebrew core submission is ready when:

- The formula is stable in the tap.
- Releases are tagged and reproducible.
- License metadata is clean.
- Tests do not require a live network tunnel or privileged route mutation.
- Formula caveats are concise and point to the supported commands.
- The project has enough maturity that Homebrew maintainers can review it as a
  normal package rather than a moving alpha experiment.

## Recommended Next Steps

1. Keep the in-repo formula as the development source of truth until the tap is
   created.
2. Create `freeq-io/homebrew-tap`.
3. Move or copy `Formula/freeq.rb` into the tap.
4. Cut the first tagged release suitable for tap testing.
5. Update the formula URL and `sha256`.
6. Test with Patrick and David using:

```bash
brew install freeq-io/tap/freeq
freeq setup
freeq gateway
freeq stop
brew upgrade freeq-io/tap/freeq
```

7. Add bottle automation.
8. Add `freeq doctor` before broad release.
9. Submit to Homebrew core after the tap path is boring and repeatable.
