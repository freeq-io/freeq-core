# VS Code Local-First AI Router

This workflow lets VS Code talk to one local OpenAI-compatible endpoint while
the router keeps ordinary coding work on this machine. Cloud routing is opt-in
and reserved for requests that exceed the local model's practical limits.

## Shape

```text
VS Code AI extension
  -> http://127.0.0.1:8123/v1/chat/completions
      -> local Ollama model for normal edits, explanations, and small reviews
      -> cloud chat endpoint only when AI_ROUTER_ALLOW_CLOUD=1 and the request
         is large or matches high-complexity terms
```

The router is intentionally small:

- local first by default
- no cloud calls unless `AI_ROUTER_ALLOW_CLOUD=1`
- no streaming yet
- append-only JSONL routing log at `.local-ai/router.log`
- OpenAI chat-completions compatible enough for VS Code extensions that support
  a custom API base URL

## Start Ollama

Install and pull a coding model once:

```bash
ollama pull qwen2.5-coder:7b
```

Confirm the model responds:

```bash
ollama run qwen2.5-coder:7b "Say ready in one short sentence."
```

## Start the Router

From the `freeq-core` repository:

```bash
AI_ROUTER_LOCAL_MODEL='qwen2.5-coder:7b' \
  python3 tools/local-ai-router.py --port 8123
```

For an intentional cloud-enabled session:

```bash
AI_ROUTER_ALLOW_CLOUD=1 \
AI_ROUTER_LOCAL_MODEL='qwen2.5-coder:7b' \
AI_ROUTER_CLOUD_MODEL='gpt-5' \
OPENAI_API_KEY="$OPENAI_API_KEY" \
  python3 tools/local-ai-router.py --port 8123
```

Leave `AI_ROUTER_ALLOW_CLOUD` unset for private/offline work.

## VS Code Extension Settings

Use any VS Code AI extension that can call an OpenAI-compatible chat endpoint
with a custom base URL. Point it at:

```text
Base URL: http://127.0.0.1:8123/v1
Model: freeq-local-first
API key: local
```

The API key value is ignored by the local router, but many extensions require a
non-empty field.

## Local-First Routing Policy

The router keeps a request local unless one of these conditions is true:

- prompt text exceeds `AI_ROUTER_MAX_LOCAL_CHARS`, default `16000`
- the prompt appears to include more than `AI_ROUTER_MAX_LOCAL_FILES`, default
  `6`, code blocks or file markers
- the prompt matches high-complexity terms such as `architecture`,
  `cryptography`, `security audit`, `threat model`, or `race condition`

Even then, it uses cloud only when `AI_ROUTER_ALLOW_CLOUD=1`. If cloud is not
enabled, the request stays local.

## Verify Routing

Send a local request:

```bash
curl -sS http://127.0.0.1:8123/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"freeq-local-first","messages":[{"role":"user","content":"Summarize the FreeQ README in one sentence."}]}'
```

Inspect the routing log:

```bash
tail -n 20 .local-ai/router.log
```

Each request records the chosen route, prompt size, and complexity reason.

## Recommended Use

Use the local router for:

- small Rust edits
- focused docs changes
- test failure explanations
- local code review of one module
- prompt generation for `scripts/run-local-ai-stripes.sh`

Use cloud escalation only for:

- cross-crate architecture decisions
- security-sensitive review where the local answer is weak
- complex concurrency or protocol reasoning
- synthesizing many files into a migration plan

Do not route customer data, secrets, private keys, credentials, or unreleased
third-party network evidence to cloud models.
