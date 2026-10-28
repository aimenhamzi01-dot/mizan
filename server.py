"""Mizan local review workbench. Start with `python server.py`."""
import json
import hashlib
import hmac
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).parent


def load_env(path=ROOT / ".env"):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env()

import meta_client  # noqa: E402
import triage  # noqa: E402
import review_store  # noqa: E402
from demo_data import DEMOS, SAMPLE_INPUT  # noqa: E402

MAX_BODY = 2 * 1024 * 1024
SAFE_MODEL_ERROR = "Model analysis failed. Check the local configuration and try again."


class Handler(BaseHTTPRequestHandler):
    server_version = "Mizan"

    def _send(self, status, body, ctype="application/json; charset=utf-8", headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; "
            "font-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        )
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _guard_local_origin(self):
        try:
            host_header = urlsplit("//" + self.headers.get("Host", "")).hostname
            host_port = urlsplit("//" + self.headers.get("Host", "")).port
        except ValueError:
            host_header, host_port = None, None
        allowed_hosts = {"127.0.0.1", "localhost"}
        if host_header not in allowed_hosts or host_port not in (None, self.server.server_port):
            self._send(403, {"error": "Local requests only."})
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                allowed = (
                    parsed.scheme == "http"
                    and parsed.hostname in allowed_hosts
                    and origin_port == self.server.server_port
                    and not parsed.username
                    and not parsed.password
                    and parsed.path in ("", "/")
                    and not parsed.query
                    and not parsed.fragment
                )
            except ValueError:
                allowed = False
            if not allowed:
                self._send(403, {"error": "Local origin only."})
                return False
        return True

    def _guard_api_token(self):
        if not urlsplit(self.path).path.startswith("/api/"):
            return True
        configured = os.environ.get("MIZAN_JUDGE_TOKEN", "").strip()
        configured_bytes = configured.encode("utf-8")
        if len(configured_bytes) < 32:
            if self.command in {"POST", "PUT", "PATCH"}:
                self.close_connection = True
            self._send(503, {"error": "Judge API authentication is not configured."})
            return False

        values = self.headers.get_all("Authorization", [])
        header = values[0] if len(values) == 1 else ""
        scheme, separator, candidate = header.partition(" ")
        well_formed = (
            len(values) == 1
            and bool(separator)
            and scheme.lower() == "bearer"
            and bool(candidate)
            and candidate == candidate.strip()
            and not any(char.isspace() for char in candidate)
        )
        supplied_digest = hashlib.sha256(candidate.encode("utf-8")).digest()
        expected_digest = hashlib.sha256(configured_bytes).digest()
        valid = hmac.compare_digest(expected_digest, supplied_digest) and well_formed
        if not valid:
            if self.command in {"POST", "PUT", "PATCH"}:
                self.close_connection = True
            self._send(
                401,
                {"error": "A valid judge Bearer token is required."},
                headers={"WWW-Authenticate": 'Bearer realm="Mizan"'},
            )
            return False
        return True

    def _json_body(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            raise RequestError(400, "Invalid Content-Length.")
        if length <= 0 or length > MAX_BODY:
            raise RequestError(413, "Request body is missing or too large.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestError(400, "Incomplete request body.")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestError(400, "Invalid JSON.")
        if not isinstance(payload, dict):
            raise RequestError(400, "JSON body must be an object.")
        return payload

    @staticmethod
    def _report_parts(payload):
        report = payload.get("report", "")
        code = payload.get("code", "")
        language = payload.get("lang", "en")
        if not isinstance(report, str) or not isinstance(code, str):
            raise RequestError(400, "Report and code must be text strings.")
        if not isinstance(language, str):
            language = "en"
        return report, code, language if language in ("en", "ar") else "en"

    @staticmethod
    def _report_path(path):
        parts = path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "api" or parts[1] != "reports":
            return None, None
        report_id = parts[2]
        action = parts[3] if len(parts) == 4 else None
        if len(parts) > 4:
            return None, None
        return report_id, action

    def do_GET(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            self._send(200, (ROOT / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/healthz":
            self._send(200, {"ok": True})
            return
        try:
            if path == "/api/health":
                self._send(200, {"ok": True, "has_key": meta_client.has_key(), "storage": "local-sqlite"})
                return
            if path == "/api/metrics":
                self._send(200, review_store.metrics())
                return
            if path == "/api/sample":
                params = parse_qs(parsed.query, keep_blank_values=True)
                kind = params.get("kind", ["valid"])[0]
                language = params.get("lang", ["en"])[0]
                if language not in ("en", "ar"):
                    language = "en"
                if kind not in SAMPLE_INPUT:
                    self._send(404, {"error": "Unknown sample."})
                    return
                self._send(200, SAMPLE_INPUT[kind][language])
                return
            if path == "/api/reports":
                params = parse_qs(parsed.query, keep_blank_values=True)
                reports = review_store.list_reports(
                    status=params.get("status", [""])[0],
                    query=params.get("q", [""])[0],
                    limit=params.get("limit", [50])[0],
                    offset=params.get("offset", [0])[0],
                )
                self._send(200, {"reports": reports})
                return
            if path.startswith("/api/reports/"):
                report_id, action = self._report_path(path)
                if not report_id:
                    self._send(404, {"error": "Not found."})
                    return
                if action == "history":
                    self._send(200, {"events": review_store.report_history(report_id)})
                elif action is None:
                    self._send(200, {"report": review_store.get_report(report_id)})
                else:
                    self._send(404, {"error": "Not found."})
                return
            self._send(404, {"error": "Not found."})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except review_store.NotFound:
            self._send(404, {"error": "Report not found."})
        except Exception:
            print("Unhandled local API error in GET", file=sys.stderr)
            self._send(500, {"error": "Internal server error."})

    def do_POST(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        try:
            payload = self._json_body()
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/api/triage":
                language = payload.get("lang", "en")
                if not isinstance(language, str) or language not in ("en", "ar"):
                    language = "en"
                demo = payload.get("demo")
                if demo:
                    if not isinstance(demo, str) or demo not in DEMOS:
                        self._send(400, {"error": "Unknown demo."})
                        return
                    self._send(200, DEMOS[demo][language])
                    return
                if payload.get("confirm_egress") is not True:
                    self._send(400, {"error": "Explicit model-egress confirmation is required."})
                    return
                report, code, language = self._report_parts(payload)
                self._send(200, triage.triage(report, code, language))
                return
            if path == "/api/reports":
                report, code, language = self._report_parts(payload)
                saved = review_store.create_report(report, code, language)
                self._send(201, {"report": saved})
                return
            report_id, action = self._report_path(path)
            if report_id and action == "analyze":
                if payload.get("confirm_egress") is not True:
                    self._send(400, {"error": "Explicit model-egress confirmation is required."})
                    return
                saved = review_store.get_report(report_id)
                if saved["status"] == "reviewed":
                    raise review_store.InvalidState("A reviewed report cannot be re-analyzed; create a new report instead.")
                analysis = triage.triage(saved["report"], saved["code"], saved["language"])
                updated = review_store.save_analysis(report_id, analysis)
                self._send(200, {"report": updated})
                return
            if report_id and action == "review":
                decision = payload.get("decision")
                reviewer = payload.get("reviewer", "")
                note = payload.get("note", "")
                if not isinstance(decision, str) or not isinstance(reviewer, str) or not isinstance(note, str):
                    raise RequestError(400, "Decision, reviewer, and note must be text strings.")
                updated = review_store.record_review(report_id, decision, reviewer, note)
                self._send(200, {"report": updated})
                return
            self._send(404, {"error": "Not found."})
        except RequestError as exc:
            self._send(exc.status, {"error": exc.message})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except review_store.NotFound:
            self._send(404, {"error": "Report not found."})
        except review_store.InvalidState as exc:
            self._send(409, {"error": str(exc)})
        except meta_client.MetaAPIError as exc:
            status = exc.status if exc.status in (401, 403, 429) else 502
            self._send(status, {"error": SAFE_MODEL_ERROR})
        except Exception:
            print("Unhandled local API error in POST", file=sys.stderr)
            self._send(500, {"error": "Internal server error."})

    def do_DELETE(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        parsed = urlsplit(self.path)
        report_id, action = self._report_path(parsed.path)
        if not report_id or action is not None:
            self._send(404, {"error": "Not found."})
            return
        try:
            review_store.delete_report(report_id)
            self._send(200, {"deleted": True, "id": report_id})
        except review_store.NotFound:
            self._send(404, {"error": "Report not found."})
        except Exception:
            print("Unhandled local API error in DELETE", file=sys.stderr)
            self._send(500, {"error": "Internal server error."})

    def do_PUT(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def do_PATCH(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def do_OPTIONS(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def do_HEAD(self):
        if not self._guard_local_origin():
            return
        if not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def log_message(self, fmt, *args):
        # Keep report text, submitted code, and provider errors out of routine logs.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    bind_host = os.environ.get("MIZAN_BIND_HOST", "127.0.0.1").strip()
    if bind_host not in {"127.0.0.1", "0.0.0.0"}:
        raise SystemExit("MIZAN_BIND_HOST must be 127.0.0.1 or 0.0.0.0.")
    review_store.init_db()
    ThreadingHTTPServer((bind_host, port), Handler).serve_forever()
