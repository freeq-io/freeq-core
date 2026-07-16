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
scripts/run-local-ai-stripes.sh --prepare --from 1 --to 10
```

Run one stripe through a local model command that reads from stdin:

```bash
LOCAL_AI_CMD='ollama run llama3.1:8b' scripts/run-local-ai-stripes.sh --run --from 2 --to 2
```

Run the remaining stripes one at a time:

```bash
LOCAL_AI_CMD='ollama run llama3.1:8b' scripts/run-local-ai-stripes.sh --run --from 2 --to 10
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
