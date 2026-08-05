#!/usr/bin/env python3
"""Local-first OpenAI-compatible chat router for VS Code tools.

The server exposes a small subset of the OpenAI chat-completions API and routes
ordinary prompts to a local Ollama model. It escalates to a cloud-compatible
chat endpoint only when explicitly enabled and the request looks large or
complex.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


LOCAL_BASE_URL = os.getenv("AI_ROUTER_LOCAL_BASE_URL", "http://127.0.0.1:11434")
LOCAL_MODEL = os.getenv("AI_ROUTER_LOCAL_MODEL", "qwen2.5-coder:7b")
CLOUD_BASE_URL = os.getenv("AI_ROUTER_CLOUD_BASE_URL", "https://api.openai.com")
CLOUD_MODEL = os.getenv("AI_ROUTER_CLOUD_MODEL", "gpt-5")
ALLOW_CLOUD = os.getenv("AI_ROUTER_ALLOW_CLOUD", "0") == "1"
MAX_LOCAL_CHARS = int(os.getenv("AI_ROUTER_MAX_LOCAL_CHARS", "16000"))
MAX_LOCAL_FILES = int(os.getenv("AI_ROUTER_MAX_LOCAL_FILES", "6"))
LOG_PATH = os.getenv("AI_ROUTER_LOG", ".local-ai/router.log")

COMPLEXITY_TERMS = (
    "architecture",
    "cross-repo",
    "cryptography",
    "security audit",
    "threat model",
    "performance regression",
    "race condition",
    "unsafe rust",
    "distributed",
    "migration plan",
    "incident",
    "root cause",
)


def log_event(event: dict[str, Any]) -> None:
    log_dir = os.path.dirname(LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    event.setdefault("time_utc", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def messages_text(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for message in messages:
        content = message.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
    return "\n".join(parts)


def complexity_reason(messages: list[dict[str, Any]]) -> str | None:
    text = messages_text(messages)
    lowered = text.lower()
    if len(text) > MAX_LOCAL_CHARS:
        return f"prompt length {len(text)} exceeds local limit {MAX_LOCAL_CHARS}"
    file_markers = lowered.count("```") // 2 + lowered.count("file:")
    if file_markers > MAX_LOCAL_FILES:
        return f"request references about {file_markers} files/blocks"
    for term in COMPLEXITY_TERMS:
        if term in lowered:
            return f"matched complexity term: {term}"
    return None


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "content-type": "application/json",
            **(headers or {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.loads(response.read().decode("utf-8"))


def local_chat(payload: dict[str, Any]) -> dict[str, Any]:
    messages = payload.get("messages", [])
    requested_model = payload.get("model")
    model = LOCAL_MODEL if requested_model in (None, "", "freeq-local-first") else requested_model
    ollama_payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": payload.get("temperature", 0.2),
        },
    }
    result = post_json(f"{LOCAL_BASE_URL.rstrip('/')}/api/chat", ollama_payload)
    content = result.get("message", {}).get("content", "")
    return openai_chat_response(model=ollama_payload["model"], content=content)


def cloud_chat(payload: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for cloud routing")
    cloud_payload = dict(payload)
    cloud_payload["model"] = CLOUD_MODEL
    cloud_payload["stream"] = False
    return post_json(
        f"{CLOUD_BASE_URL.rstrip('/')}/v1/chat/completions",
        cloud_payload,
        headers={"authorization": f"Bearer {api_key}"},
    )


def openai_chat_response(model: str, content: str) -> dict[str, Any]:
    return {
        "id": f"local-ai-router-{int(time.time())}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


class RouterHandler(BaseHTTPRequestHandler):
    server_version = "FreeQLocalAIRouter/0.1"

    def do_GET(self) -> None:
        if self.path == "/v1/models":
            self.send_json(
                {
                    "object": "list",
                    "data": [
                        {"id": "freeq-local-first", "object": "model"},
                        {"id": LOCAL_MODEL, "object": "model"},
                    ],
                }
            )
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            messages = payload.get("messages", [])
            reason = complexity_reason(messages)
            route = "cloud" if reason and ALLOW_CLOUD else "local"
            if route == "cloud":
                response = cloud_chat(payload)
            else:
                response = local_chat(payload)
            log_event(
                {
                    "route": route,
                    "reason": reason or "local-default",
                    "allow_cloud": ALLOW_CLOUD,
                    "requested_model": payload.get("model"),
                    "local_model": LOCAL_MODEL,
                    "cloud_model": CLOUD_MODEL if route == "cloud" else None,
                    "prompt_chars": len(messages_text(messages)),
                }
            )
            self.send_json(response)
        except (RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
            log_event({"route": "error", "error": str(exc)})
            self.send_json({"error": {"message": str(exc)}}, status=502)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("router: " + format % args + "\n")

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the FreeQ local-first AI router.")
    parser.add_argument("--host", default=os.getenv("AI_ROUTER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("AI_ROUTER_PORT", "8123")))
    args = parser.parse_args()

    log_event(
        {
            "event": "start",
            "host": args.host,
            "port": args.port,
            "local_base_url": LOCAL_BASE_URL,
            "local_model": LOCAL_MODEL,
            "allow_cloud": ALLOW_CLOUD,
            "cloud_base_url": CLOUD_BASE_URL if ALLOW_CLOUD else None,
            "cloud_model": CLOUD_MODEL if ALLOW_CLOUD else None,
        }
    )
    server = ThreadingHTTPServer((args.host, args.port), RouterHandler)
    print(f"FreeQ local AI router listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
