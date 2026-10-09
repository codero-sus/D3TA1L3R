"""A stand-in for Cortex LLM Hoster, used to prove the backend end to end.

Cortex serves a GGUF you own over an OpenAI-compatible API. This stub speaks the
same two routes so the integration can be exercised without llama.cpp, a model
file, or 4 GB of RAM: it echoes back which model id D3TA1L3R asked for, which is
exactly what `--cortex-model auto` has to resolve.

    python scripts/fake_cortex.py [port]

Not part of the package; a development aid only.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODELS = ["qwen-local", "phi-local"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # quiet by default
        sys.stderr.write("cortex-stub: " + (fmt % args) + "\n")

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        if self.path == "/v1/models":
            self._send({"object": "list", "data": [{"id": name} for name in MODELS]})
        else:
            self._send({"error": f"no route {self.path}"}, status=404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if self.path != "/v1/chat/completions":
            self._send({"error": f"no route {self.path}"}, status=404)
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send({"error": "bad json"}, status=400)
            return
        asked = payload.get("model")
        question = ""
        for message in reversed(payload.get("messages") or []):
            if message.get("role") == "user":
                question = str(message.get("content") or "")
                break
        answer = (
            f"[stub cortex, model={asked}] I was asked: {question[:120]!r}. "
            "A real Cortex would answer this from your GGUF; see F1-001 for the "
            "first finding in the digest."
        )
        sys.stderr.write(f"cortex-stub: answering with model={asked!r}\n")
        self._send(
            {
                "object": "chat.completion",
                "model": asked,
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": answer},
                     "finish_reason": "stop"}
                ],
            }
        )


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8624
    print(f"cortex stub on http://127.0.0.1:{port} serving {MODELS}", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
