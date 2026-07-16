#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TASK_FILE="${LOCAL_AI_TASK_FILE:-docs/local-ai-dev-cycle.md}"
FROM=1
TO=10
MODE="prepare"
OUT_ROOT="${LOCAL_AI_OUT_ROOT:-.local-ai/stripes}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
PROCESS_CHECK=1
STOP_ON_DIRTY=1
SLEEP_SECONDS="${LOCAL_AI_STRIPE_SLEEP_SECONDS:-5}"
PROCESS_PATTERN="${LOCAL_AI_PROCESS_PATTERN:-ollama|llama|llama.cpp|llama-server|llamacpp|mlx|local-ai|text-generation-webui|kobold|vllm}"

usage() {
  cat <<'EOF'
Prepare or run the local AI dev-cycle stripes.

Default behavior prepares prompt files for stripes 1-10 from:
  docs/local-ai-dev-cycle.md

Usage:
  scripts/run-local-ai-stripes.sh [options]

Options:
  --prepare             write prompt files only; default
  --run                 run each prompt through LOCAL_AI_CMD
  --list                list available stripes and exit
  --check-processes     report matching local AI processes and exit
  --from N              first stripe number; default 1
  --to N                last stripe number; default 10
  --out-dir PATH        output directory; default .local-ai/stripes/<timestamp>
  --no-process-check    skip existing local AI process guard
  --keep-going-dirty    do not stop when a stripe leaves the worktree dirty
  --sleep SECONDS       pause between stripes in --run mode; default 5
  --help                show this help

Run mode requires LOCAL_AI_CMD. The command must read the prompt from stdin.

Examples:
  scripts/run-local-ai-stripes.sh --prepare
  LOCAL_AI_CMD='ollama run llama3.1:8b' scripts/run-local-ai-stripes.sh --run --from 2 --to 2
  LOCAL_AI_CMD='./llama-cli -m model.gguf -p -' scripts/run-local-ai-stripes.sh --run --from 2 --to 10

Safety:
  - The script refuses to run if another local AI process is already detected,
    unless ALLOW_EXISTING_LOCAL_AI=1 or --no-process-check is used.
  - In --run mode, it stops after a stripe if the Git worktree becomes dirty,
    unless --keep-going-dirty is used.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

is_integer() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prepare) MODE="prepare"; shift ;;
    --run) MODE="run"; shift ;;
    --list) MODE="list"; shift ;;
    --check-processes) MODE="check-processes"; shift ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --to) TO="${2:-}"; shift 2 ;;
    --out-dir) OUT_ROOT="${2:-}"; RUN_ID=""; shift 2 ;;
    --no-process-check) PROCESS_CHECK=0; shift ;;
    --keep-going-dirty) STOP_ON_DIRTY=0; shift ;;
    --sleep) SLEEP_SECONDS="${2:-}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

is_integer "$FROM" || die "--from must be a positive integer"
is_integer "$TO" || die "--to must be a positive integer"
is_integer "$SLEEP_SECONDS" || die "--sleep must be a non-negative integer"
[ "$FROM" -le "$TO" ] || die "--from must be less than or equal to --to"
[ -f "$TASK_FILE" ] || die "missing task file: $TASK_FILE"

if [ -n "$RUN_ID" ]; then
  OUT_DIR="$OUT_ROOT/$RUN_ID"
else
  OUT_DIR="$OUT_ROOT"
fi

list_stripes() {
  awk '/^## [0-9]+\. / { sub(/^## /, ""); print }' "$TASK_FILE"
}

extract_stripe() {
  local stripe="$1"
  awk -v stripe="$stripe" '
    $0 ~ "^## " stripe "\\. " { found=1; print; next }
    found && $0 ~ "^## [0-9]+\\. " { exit }
    found { print }
  ' "$TASK_FILE"
}

check_local_ai_processes() {
  local matches
  set +e
  matches="$(ps aux 2>/dev/null | awk -v pattern="$PROCESS_PATTERN" '
    BEGIN { IGNORECASE=1 }
    $0 ~ pattern && $0 !~ /run-local-ai-stripes/ && $0 !~ /awk -v pattern/ { print }
  ')"
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "Could not inspect processes with ps. Run this manually if needed:" >&2
    echo "  ps aux | rg -i '$PROCESS_PATTERN'" >&2
    return 2
  fi
  if [ -n "$matches" ]; then
    echo "$matches"
    return 1
  fi
  return 0
}

write_prompt() {
  local stripe="$1"
  local section="$2"
  local prompt_file="$OUT_DIR/stripe-$(printf '%02d' "$stripe").prompt.txt"
  cat > "$prompt_file" <<EOF
You are the local FreeQ SLM development worker.

Repository:
  $REPO_ROOT

Hard rules:
  - Work only on the stripe below.
  - Read the referenced files before editing.
  - Keep changes scoped.
  - Do not use network access.
  - Do not touch cryptography behavior unless explicitly instructed.
  - Run the listed verification commands.
  - Report exact files changed and exact commands run.
  - If you cannot safely complete the stripe, stop and report why.

$section
EOF
  printf '%s\n' "$prompt_file"
}

if [ "$MODE" = "list" ]; then
  list_stripes
  exit 0
fi

if [ "$MODE" = "check-processes" ]; then
  set +e
  process_output="$(check_local_ai_processes)"
  process_rc=$?
  set -e
  if [ "$process_rc" -eq 0 ]; then
    echo "No matching local AI processes found."
    exit 0
  fi
  echo "$process_output" >&2
  exit "$process_rc"
fi

if [ "$PROCESS_CHECK" -eq 1 ] && [ "${ALLOW_EXISTING_LOCAL_AI:-0}" != "1" ]; then
  set +e
  process_output="$(check_local_ai_processes)"
  process_rc=$?
  set -e
  if [ "$process_rc" -eq 1 ]; then
    echo "A matching local AI process appears to be running:" >&2
    echo "$process_output" >&2
    echo >&2
    echo "Stop it first, or rerun with ALLOW_EXISTING_LOCAL_AI=1 if this is intentional." >&2
    exit 1
  elif [ "$process_rc" -ne 0 ]; then
    echo "$process_output" >&2
    echo "Could not verify local AI process state. Rerun outside the sandbox, or use --no-process-check if you have checked manually." >&2
    exit "$process_rc"
  fi
fi

if [ "$MODE" = "run" ] && [ -z "${LOCAL_AI_CMD:-}" ]; then
  die "--run requires LOCAL_AI_CMD, for example: LOCAL_AI_CMD='ollama run llama3.1:8b'"
fi

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.log"
{
  echo "run_id=${RUN_ID:-manual}"
  echo "task_file=$TASK_FILE"
  echo "from=$FROM"
  echo "to=$TO"
  echo "mode=$MODE"
  echo "started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$SUMMARY"

for stripe in $(seq "$FROM" "$TO"); do
  section="$(extract_stripe "$stripe")"
  if [ -z "$section" ]; then
    die "stripe $stripe not found in $TASK_FILE"
  fi

  prompt_file="$(write_prompt "$stripe" "$section")"
  echo "Prepared stripe $stripe prompt:"
  echo "  $prompt_file"
  echo "stripe_$stripe.prompt=$prompt_file" >> "$SUMMARY"

  if [ "$MODE" != "run" ]; then
    continue
  fi

  log_file="$OUT_DIR/stripe-$(printf '%02d' "$stripe").run.log"
  echo "Running stripe $stripe with LOCAL_AI_CMD..."
  echo "stripe_$stripe.log=$log_file" >> "$SUMMARY"
  set +e
  bash -lc "$LOCAL_AI_CMD" < "$prompt_file" > "$log_file" 2>&1
  rc=$?
  set -e
  echo "stripe_$stripe.exit_code=$rc" >> "$SUMMARY"
  if [ "$rc" -ne 0 ]; then
    echo "Stripe $stripe failed with exit code $rc. See:"
    echo "  $log_file"
    exit "$rc"
  fi

  if [ "$STOP_ON_DIRTY" -eq 1 ] && ! git diff --quiet; then
    echo "Stripe $stripe left the worktree dirty. Review and commit before continuing."
    echo "Resume with:"
    echo "  LOCAL_AI_CMD='${LOCAL_AI_CMD}' scripts/run-local-ai-stripes.sh --run --from $((stripe + 1)) --to $TO"
    exit 0
  fi

  if [ "$stripe" -lt "$TO" ] && [ "$SLEEP_SECONDS" -gt 0 ]; then
    sleep "$SLEEP_SECONDS"
  fi
done

echo "Local AI stripe $MODE complete."
echo "Output:"
echo "  $OUT_DIR"
