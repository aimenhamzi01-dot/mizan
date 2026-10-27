"""Mizan (ميزان): run `python server.py` and open http://localhost:8000"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent


def load_env(path=ROOT / ".env"):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()

import meta_client  # noqa: E402
import triage  # noqa: E402
from demo_data import DEMOS, SAMPLE_INPUT  # noqa: E402

MAX_BODY = 2 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "Mizan/0.1"

    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (ROOT / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/health":
            self._send(200, {"ok": True, "has_key": meta_client.has_key()})
        elif self.path.startswith("/api/sample"):
            kind = self.path.split("kind=")[-1] if "kind=" in self.path else "valid"
            lang = "ar" if "lang=ar" in self.path else "en"
            kind = kind.split("&")[0]
            if kind not in SAMPLE_INPUT:
                return self._send(404, {"error": "unknown sample"})
            self._send(200, SAMPLE_INPUT[kind][lang])
        else:
            self._send(404, {"error": "Not found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length <= 0 or length > MAX_BODY:
                return self._send(413, {"error": "Request body missing or too large."})
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "Invalid JSON."})

        lang = payload.get("lang") if payload.get("lang") in ("ar", "en") else "en"
        try:
            if self.path == "/api/triage":
                demo = payload.get("demo")
                if demo:
                    if demo not in DEMOS:
                        return self._send(400, {"error": "unknown demo"})
                    return self._send(200, DEMOS[demo][lang])
                self._send(200, triage.triage(payload.get("report"), payload.get("code"), lang))
            else:
                self._send(404, {"error": "Not found"})
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except meta_client.MetaAPIError as e:
            status = e.status if e.status in (401, 403, 429) else 502
            self._send(status, {"error": str(e)})
        except Exception as e:
            print("Unhandled error:", repr(e), file=sys.stderr)
            self._send(500, {"error": "Something went wrong on the server."})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    key = "found" if meta_client.has_key() else "MISSING (demo cases still work)"
    print("Mizan on http://localhost:%d  |  API key: %s" % (port, key))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
