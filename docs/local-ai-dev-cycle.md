# Local AI Dev Cycle

Use this queue for small local-model development passes. Work one item at a
time. Each item should produce a patch, a clear no-change report, or a failing
test that explains the next fix.

Rules for each item:

- Read the referenced files first.
- Keep changes scoped to the item.
- Do not use network access.
- Do not touch cryptography behavior unless the item explicitly says so.
- Run the listed verification commands.
- Report exact files changed and exact commands run.

## Runner

Use `scripts/run-local-ai-stripes.sh` to prepare or run this queue.

First check whether a local model process is already running:

```bash
scripts/run-local-ai-stripes.sh --check-processes
```

Prepare prompt files without launching a model:

```bash
scripts/run-local-ai-stripes.sh --prepare --from 1 --to 16
```

Run one stripe through a local model command that reads from stdin:

```bash
LOCAL_AI_CMD='ollama run qwen2.5-coder:7b' scripts/run-local-ai-stripes.sh --run --from 2 --to 2
```

Run the remaining stripes one at a time:

```bash
LOCAL_AI_CMD='ollama run qwen2.5-coder:7b' scripts/run-local-ai-stripes.sh --run --from 2 --to 16
```

Run the fat documentation batch, intended to keep a small local coding model
busy for a longer session and produce substantial reviewable output:

```bash
ALLOW_EXISTING_LOCAL_AI=1 \
LOCAL_AI_CMD='ollama run qwen2.5-coder:7b' \
  scripts/run-local-ai-stripes.sh --run --from 12 --to 16 --keep-going-dirty --sleep 1
```

The runner stops if it detects an existing local AI process, unless
`ALLOW_EXISTING_LOCAL_AI=1` is set. In `--run` mode, it also stops after any
stripe that leaves the Git worktree dirty so the change can be reviewed before
the next stripe starts.

## 1. Pre-Commit Setup Harness

Status: done in `scripts/git-pre-commit.sh`.

Prompt:

```text
Focus only on wiring scripts/test-setup-flow.sh into scripts/git-pre-commit.sh.
Read scripts/git-pre-commit.sh first. Add the setup flow harness in the least
surprising existing style. Do not change unrelated checks. Avoid network access.
Run bash -n scripts/git-pre-commit.sh and scripts/test-setup-flow.sh.
```

Verify:

```bash
bash -n scripts/git-pre-commit.sh
scripts/test-setup-flow.sh
```

## 2. Normalize Env Parsing

Goal: remove avoidable `source` usage for received peer files and document any
remaining trusted local env sourcing.

Prompt:

```text
Focus only on env parsing safety. Search for ". $PEER_ENV", ". \"$PEER_ENV\"",
". $LOCAL_ENV", ". \"$LOCAL_ENV\"", and similar source usage in scripts.
Received peer.env files must be parsed through scripts/setup/freeq-validate-peer-env.sh
or an equally safe parser. Local node.env may remain trusted only if the script
never accepts it from the peer drop folder. Make the smallest safe patch and
update scripts/test-setup-flow.sh if needed.
```

Verify:

```bash
rg -n "\\. .*ENV|source .*ENV" scripts
bash -n scripts/setup/*.sh scripts/perf/*.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 3. Shorten Setup Profile Comments

Goal: make generated `~/FreeQ/freeq-setup.conf` easier for a novice to edit.

Prompt:

```text
Focus only on the config text emitted by write_config in
scripts/setup/freeq-setup-macos.sh. Make comments shorter and clearer. Preserve
all variables and behavior. Add or update a setup harness assertion that the
generated profile contains FREEQ_PUBLIC_ENDPOINT and no FREEQ_PEER_ENDPOINT.
```

Verify:

```bash
bash -n scripts/setup/freeq-setup-macos.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 4. Network Failure UX

Goal: failed clone/fetch/pull/curl installer paths should say what failed and
what to try next.

Prompt:

```text
Focus only on network/dependency failure messages in scripts/setup/freeq-setup-macos.sh.
Find git clone, git fetch, git pull, curl-based Rust install, and Homebrew install
paths. Improve messages for offline, DNS, or remote failures without changing the
successful path. Avoid network access. Add a lightweight dry-run or shell-level
test if practical.
```

Verify:

```bash
bash -n scripts/setup/freeq-setup-macos.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 5. Endpoint Prompt Clarity

Goal: make `FREEQ_PUBLIC_ENDPOINT` understandable for someone who does not know
network jargon.

Prompt:

```text
Focus only on wording for FREEQ_PUBLIC_ENDPOINT in setup prompts, setup summary,
docs/setup-macos.md, and docs/perf-macos-quickstart.md. Explain that it is the
address and UDP port the other Mac can reach. Keep it concise. Do not reintroduce
FREEQ_PEER_ENDPOINT.
```

Verify:

```bash
rg -n "FREEQ_PEER_ENDPOINT|PEER_ENDPOINT|--peer-endpoint" scripts docs
scripts/test-setup-flow.sh
```

## 6. Setup Profile Validator

Goal: add a validator for `~/FreeQ/freeq-setup.conf`.

Prompt:

```text
Create scripts/setup/freeq-validate-setup-conf.sh. It should validate
FREEQ_NODE_NAME, FREEQ_OVERLAY_ADDRESS, FREEQ_LISTEN_ADDR, FREEQ_PUBLIC_ENDPOINT
when nonblank, FREEQ_PEER_SSH_USER when nonblank, and FREEQ_PEER_SSH_PORT.
It should not require FREEQ_PUBLIC_ENDPOINT to be set, but should warn clearly.
Wire it into scripts/test-setup-flow.sh.
```

Verify:

```bash
bash -n scripts/setup/freeq-validate-setup-conf.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 7. Earlier Overlay Collision Check

Goal: duplicate local/peer overlay addresses should fail before writing a config.

Prompt:

```text
Focus only on duplicate overlay address handling in scripts/setup/freeq-render-config.sh.
Ensure the check happens before output config creation and the message tells the
user which side must rerun setup with a different overlay address. Add a test to
scripts/test-setup-flow.sh that creates duplicate overlay env files and expects
the failure.
```

Verify:

```bash
bash -n scripts/setup/freeq-render-config.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 8. Messy Peer Drop Folder UX

Goal: zero, multiple, wrong, or private files in `02-put-peer-file-here` should
produce consistent messages.

Prompt:

```text
Focus only on peer file discovery and validation messages in setup/render/start/perf
scripts. Add setup harness cases for zero peer files, multiple peer files, and a
private node.env placed in the peer drop folder. Keep messages plain and tell the
user exactly which visible folder to fix.
```

Verify:

```bash
bash -n scripts/setup/*.sh scripts/perf/*.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 9. Dependency Matrix

Goal: document required and optional dependencies in one terse table.

Prompt:

```text
Create docs/setup-dependencies.md. Include dependency, required/optional, why it
is needed, install command, and what happens if missing. Cover git, Xcode command
line tools, Rust/cargo, Homebrew, iperf3, jq, ssh, curl, and sudo. Link it from
docs/setup-macos.md and docs/perf-macos-quickstart.md.
```

Verify:

```bash
rg -n "setup-dependencies" docs
scripts/test-setup-flow.sh
```

## 10. One-Command Doctor

Goal: give users one command that reports setup health and the next action.

Prompt:

```text
Create scripts/setup/freeq-doctor-macos.sh. It should check macOS, dependency
presence, visible setup folder, setup config, local node.env, received peer.env,
peer env validation, built binaries, and rendered freeq.toml. It should not
start freeqd or require sudo. Each failed check should print one next action.
Add at least one happy-path and one missing-peer-file test to scripts/test-setup-flow.sh.
```

Verify:

```bash
bash -n scripts/setup/freeq-doctor-macos.sh scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
```

## 11. Brew-Style Operator Command Map

Goal: give normal users one clear, durable command reference for install,
update, setup, health checks, gateway/direct connection, status, and rollback.

This is intentionally a fat documentation/harness stripe. It should not touch
Rust, daemon behavior, cryptography, route management, sudo behavior, generated
site assets, or platform installers.

Prompt:

```text
Create docs/freeq-operator-command-map.md as the plain-English command map for
FreeQ's brew-style user experience.

Read README.md, docs/simple-install.md, docs/setup-macos.md,
docs/perf-macos-quickstart.md, docs/homebrew-install-maintenance-strategy.md,
docs/platform-installation-framework.md, scripts/setup/freeq-doctor-macos.sh,
and scripts/test-setup-flow.sh before editing.

The new doc should cover:
  - brew install freeq
  - brew upgrade freeq
  - freeq setup
  - freeq doctor
  - freeq gateway status
  - freeq gateway
  - freeq status
  - freeq stop
  - when direct node-to-node is enough
  - when a gateway/rendezvous point is needed
  - what PASS, FAIL, and Next mean
  - what FreeQ does not do: it does not replace radio-layer security, does not
    secure arbitrary RF waveforms, and does not require a gateway when direct
    node-to-node reachability exists

Link this new command map from README.md, docs/simple-install.md,
docs/setup-macos.md, docs/perf-macos-quickstart.md, and
docs/homebrew-install-maintenance-strategy.md.

Add guardrail assertions to scripts/test-setup-flow.sh that prove the new doc
exists, is linked from the listed docs, and contains the core commands and the
direct/gateway/non-RF-security language.

Do not edit CLI Rust code, daemon code, networking scripts, generated docs/assets
bundles, or Homebrew formula code in this stripe. If you think code is needed,
stop and report why instead of changing code.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "freeq-operator-command-map|freeq doctor|freeq gateway status|freeq stop|direct node-to-node|does not replace radio-layer security" README.md docs scripts/test-setup-flow.sh
git diff --name-only
```

## 12. Fat Batch: Operator Command Map Patch

Goal: produce a complete, reviewable patch for a durable operator command map.

This stripe is designed for substantial local-model output. Produce a unified
diff, not just advice. If you cannot safely produce a diff, produce complete
file contents for every changed file.

Hard scope:

- Documentation and `scripts/test-setup-flow.sh` assertions only.
- Do not edit Rust, daemon code, networking scripts, generated site assets,
  Homebrew formula code, cryptography, route management, or sudo behavior.
- Do not claim Linux, Windows, or gateway hardware support unless the referenced
  docs already mark it supported.

Prompt:

```text
Create a complete unified diff for docs/freeq-operator-command-map.md and the
minimal links/assertions needed around it.

Read these files first:
  - README.md
  - docs/simple-install.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/homebrew-install-maintenance-strategy.md
  - docs/platform-installation-framework.md
  - docs/federal-sof-racer-positioning.md
  - scripts/setup/freeq-doctor-macos.sh
  - scripts/test-setup-flow.sh

The new doc must be written for a normal user. It must explain:
  - brew install freeq
  - brew upgrade freeq
  - freeq setup
  - freeq doctor
  - freeq gateway status
  - freeq gateway
  - freeq status
  - freeq stop
  - direct node-to-node when endpoints can reach each other
  - gateway/rendezvous when direct reachability is blocked by hotel Wi-Fi,
    airport Wi-Fi, CGNAT, Starlink, cellular, guest networks, or firewalls
  - PASS means the check succeeded
  - FAIL means the check did not succeed
  - Next means the next action to take
  - FreeQ protects routable digital traffic between trusted nodes
  - FreeQ does not replace radio-layer security, does not secure arbitrary RF
    waveforms, and does not require a gateway when direct reachability exists

Link the new doc from:
  - README.md
  - docs/simple-install.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/homebrew-install-maintenance-strategy.md

Add assertions to scripts/test-setup-flow.sh that check the links and the core
phrases above.

Output format:
  1. A short summary.
  2. A complete unified diff that can be applied with git apply.
  3. The exact verification commands to run.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "freeq-operator-command-map|freeq doctor|freeq gateway status|freeq stop|direct node-to-node|does not replace radio-layer security" README.md docs scripts/test-setup-flow.sh
git diff --name-only
```

## 13. Fat Batch: Captive Wi-Fi And Rollback Runbook

Goal: produce a field runbook for captive Wi-Fi, hotel networks, airport
networks, hotspot fallback, FreeQ rollback, and normal network restoration.

This stripe should generate a substantial document and test assertions, not
just a paragraph.

Hard scope:

- Documentation and `scripts/test-setup-flow.sh` assertions only.
- Do not edit rollback scripts, network scripts, Rust, daemon code, generated
  site assets, Homebrew formula code, cryptography, route management, or sudo
  behavior.
- Do not tell normal users to manually delete routes, edit hidden files, or run
  raw `sudo kill`.

Prompt:

```text
Create a complete unified diff for docs/captive-wifi-rollback-runbook.md and
the minimal links/assertions needed around it.

Read these files first:
  - docs/simple-install.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/homebrew-install-maintenance-strategy.md
  - scripts/setup/freeq-stop-macos.sh
  - scripts/setup/freeq-doctor-macos.sh
  - scripts/test-setup-flow.sh

The new runbook must explain:
  - why captive networks can be confusing after testing overlays
  - when to run freeq stop
  - when to run freeq doctor
  - when to use freeq gateway status
  - how to return to normal networking without hidden-folder work
  - how to handle hotel Wi-Fi, airport Wi-Fi, club Wi-Fi, iPhone hotspot, and
    gateway tests
  - what FreeQ-owned cleanup means
  - what freeq stop does at a high level
  - what PASS, FAIL, and Next mean
  - when to ask for help and what text to copy

Link it from:
  - docs/simple-install.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/homebrew-install-maintenance-strategy.md

Add setup-flow assertions that check the new doc exists, is linked, and contains:
  - captive Wi-Fi
  - hotel Wi-Fi
  - iPhone hotspot
  - freeq stop
  - freeq doctor
  - normal networking
  - FreeQ-owned

Output format:
  1. A short summary.
  2. A complete unified diff that can be applied with git apply.
  3. The exact verification commands to run.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "captive-wifi-rollback-runbook|captive Wi-Fi|iPhone hotspot|normal networking|FreeQ-owned" docs scripts/test-setup-flow.sh
git diff --name-only
```

## 14. Fat Batch: Gateway And Rendezvous Field Guide

Goal: produce a clear field guide explaining direct node-to-node operation,
gateway/rendezvous operation, and what gateways do and do not do.

Hard scope:

- Documentation and `scripts/test-setup-flow.sh` assertions only.
- Do not edit Rust, daemon code, networking scripts, generated site assets,
  Homebrew formula code, cryptography, route management, or sudo behavior.
- Do not claim a gateway is always required.
- Do not claim FreeQ secures arbitrary RF waveforms or replaces approved
  radio-layer security.

Prompt:

```text
Create a complete unified diff for docs/gateway-rendezvous-field-guide.md and
the minimal links/assertions needed around it.

Read these files first:
  - README.md
  - docs/architecture.md
  - docs/simple-install.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/platform-installation-framework.md
  - docs/federal-sof-racer-positioning.md
  - scripts/test-setup-flow.sh

The new guide must explain:
  - FreeQ traffic can go direct node-to-node when reachable
  - a gateway/rendezvous point helps when direct reachability is blocked
  - common blockers: NAT, CGNAT, hotel Wi-Fi, airport Wi-Fi, Starlink, cellular,
    enterprise guest networks, restrictive firewalls
  - the gateway is not magic and does not replace underlying bearer networks
  - FreeQ wraps routable digital traffic between trusted endpoints
  - FreeQ can use public internet, fiber, LTE, SATCOM, Starlink, Wi-Fi,
    tactical backhaul, or private networks as bearers
  - FreeQ does not replace radio-layer security or secure arbitrary RF waveforms
  - how to use freeq gateway status, freeq gateway, freeq status, freeq doctor,
    and freeq stop in the gateway path

Link it from:
  - README.md
  - docs/setup-macos.md
  - docs/perf-macos-quickstart.md
  - docs/platform-installation-framework.md
  - docs/federal-sof-racer-positioning.md

Add setup-flow assertions that check the new doc exists, is linked, and contains
the direct/gateway/bearer/non-RF-security language above.

Output format:
  1. A short summary.
  2. A complete unified diff that can be applied with git apply.
  3. The exact verification commands to run.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "gateway-rendezvous-field-guide|direct node-to-node|gateway/rendezvous|routable digital traffic|radio-layer security|arbitrary RF waveforms" README.md docs scripts/test-setup-flow.sh
git diff --name-only
```

## 15. Fat Batch: Platform Support Readiness Map

Goal: produce a practical support map that distinguishes active, planned,
stubbed, and unsupported installation paths across macOS, Linux, Windows,
gateway hardware, containers, and cloud gateways.

Hard scope:

- Documentation and `scripts/test-setup-flow.sh` assertions only.
- Do not edit platform installers, Rust, daemon code, networking scripts,
  generated site assets, Homebrew formula code, cryptography, route management,
  or sudo behavior.
- Do not mark Linux, Windows, gateway hardware, containers, or cloud gateway
  install paths supported unless the existing docs already say so.

Prompt:

```text
Create a complete unified diff for docs/platform-support-readiness-map.md and
the minimal links/assertions needed around it.

Read these files first:
  - docs/platform-installation-framework.md
  - docs/linux-supported-acceptance.md
  - docs/linux-install-code-mill-brief.md
  - docs/homebrew-install-maintenance-strategy.md
  - docs/simple-install.md
  - README.md
  - scripts/test-setup-flow.sh

The new map must include:
  - macOS workstation: active alpha path
  - Linux workstation: planned/readiness-gated path
  - Linux gateway/server: stubbed/planned path
  - Windows workstation: stubbed/planned path
  - Windows gateway/server: stubbed/planned path
  - container gateway: stubbed/planned path
  - cloud managed gateway: stubbed/planned path
  - what install command is expected for each target eventually
  - what service model is expected for each target eventually
  - what acceptance evidence is required before calling a target supported
  - the shared command vocabulary: freeq setup, freeq gateway, freeq gateway
    status, freeq doctor, freeq status, freeq stop
  - the package-manager lifecycle: install, update, uninstall

Link it from:
  - README.md
  - docs/platform-installation-framework.md
  - docs/homebrew-install-maintenance-strategy.md
  - docs/simple-install.md

Add setup-flow assertions that check the new doc exists, is linked, and contains:
  - macOS workstation
  - Linux workstation
  - Linux gateway/server
  - Windows workstation
  - container gateway
  - cloud managed gateway
  - readiness-gated
  - freeq doctor

Output format:
  1. A short summary.
  2. A complete unified diff that can be applied with git apply.
  3. The exact verification commands to run.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "platform-support-readiness-map|readiness-gated|Linux workstation|Windows workstation|container gateway|cloud managed gateway" README.md docs scripts/test-setup-flow.sh
git diff --name-only
```

## 16. Fat Batch: Federal And Enterprise Positioning FAQ

Goal: produce a careful FAQ that helps explain FreeQ to enterprise and federal
readers without overstating procurement, accreditation, RF, COMSEC, gateway, or
platform-support claims.

Hard scope:

- Documentation and `scripts/test-setup-flow.sh` assertions only.
- Do not edit Rust, daemon code, networking scripts, generated site assets,
  Homebrew formula code, cryptography, route management, or sudo behavior.
- Do not claim awards, procurement eligibility, ATO, Type 1, COMSEC replacement,
  radio replacement, Linux support, Windows support, or production gateway
  support.

Prompt:

```text
Create a complete unified diff for docs/federal-enterprise-positioning-faq.md
and the minimal links/assertions needed around it.

Read these files first:
  - README.md
  - docs/architecture.md
  - docs/federal-sof-racer-positioning.md
  - docs/platform-installation-framework.md
  - docs/homebrew-install-maintenance-strategy.md
  - docs/simple-install.md
  - scripts/test-setup-flow.sh

The FAQ must be cautious and useful. It should answer:
  - What does FreeQ protect?
  - Does FreeQ replace radios, SATCOM, Link 16, Type 1, COMSEC, or radio-layer
    security?
  - Does FreeQ require a gateway?
  - When is a gateway/rendezvous useful?
  - What bearer networks can FreeQ use?
  - What is the current supported install path?
  - What platform paths are planned but not supported yet?
  - What can be demonstrated now?
  - What claims should not be made?
  - How could this be positioned for SOF-RACER or similar federal innovation
    channels without claiming award, endorsement, procurement eligibility, or
    accreditation?

Link it from:
  - README.md
  - docs/federal-sof-racer-positioning.md
  - docs/platform-installation-framework.md
  - docs/homebrew-install-maintenance-strategy.md

Add setup-flow assertions that check the new doc exists, is linked, and contains:
  - routable digital traffic
  - trusted nodes
  - gateway/rendezvous
  - does not replace radios
  - does not replace COMSEC
  - no award claim
  - no accreditation claim
  - SOF-RACER

Output format:
  1. A short summary.
  2. A complete unified diff that can be applied with git apply.
  3. The exact verification commands to run.
```

Verify:

```bash
bash -n scripts/test-setup-flow.sh
scripts/test-setup-flow.sh
rg -n "federal-enterprise-positioning-faq|routable digital traffic|trusted nodes|does not replace radios|does not replace COMSEC|no award claim|SOF-RACER" README.md docs scripts/test-setup-flow.sh
git diff --name-only
```
