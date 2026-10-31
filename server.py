"""Mizan self-hosted team review workbench. Start with `python server.py`."""
import hashlib
import hmac
import json
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

import auth_store  # noqa: E402
import meta_client  # noqa: E402
import review_store  # noqa: E402
import secret_store  # noqa: E402
import triage  # noqa: E402
from demo_data import DEMOS, SAMPLE_INPUT  # noqa: E402

MAX_BODY = 2 * 1024 * 1024
SAFE_MODEL_ERROR = "Model analysis failed. Check your local model-key configuration and try again."
READ_ROLES = {"admin", "analyst", "reviewer", "viewer"}
ANALYZE_ROLES = {"admin", "analyst"}
REVIEW_ROLES = {"admin", "reviewer"}


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

    @staticmethod
    def _csv_env(name):
        return {item.strip().lower() for item in os.environ.get(name, "").split(",") if item.strip()}

    def _guard_local_origin(self):
        """Loopback-only by default; remote self-hosting requires exact allow-lists."""
        raw_host = self.headers.get("Host", "")
        try:
            host_parts = urlsplit("//" + raw_host)
            hostname = (host_parts.hostname or "").lower()
            authority = raw_host.lower()
            host_port = host_parts.port
            malformed_host = not host_parts.netloc or bool(host_parts.username or host_parts.password)
        except ValueError:
            hostname, authority, host_port, malformed_host = "", "", None, True
        local_hosts = {"127.0.0.1", "localhost", "[::1]", "::1"}
        allowed_hosts = self._csv_env("MIZAN_ALLOWED_HOSTS")
        local_host_ok = hostname in local_hosts and host_port in (None, self.server.server_port)
        configured_host_ok = authority in allowed_hosts or hostname in allowed_hosts
        if malformed_host or not (local_host_ok or configured_host_ok):
            self._send(403, {"error": "Host is not allowed. Configure MIZAN_ALLOWED_HOSTS for a trusted private proxy."})
            return False

        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                local_origin_ok = (
                    parsed.scheme == "http" and parsed.hostname in local_hosts
                    and origin_port == self.server.server_port and not parsed.username and not parsed.password
                    and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                )
                configured_origins = self._csv_env("MIZAN_ALLOWED_ORIGINS")
                configured_origin_ok = origin.rstrip("/").lower() in configured_origins
                if not (local_origin_ok or configured_origin_ok):
                    raise ValueError("origin not allowed")
            except ValueError:
                self._send(403, {"error": "Origin is not allowed."})
                return False
        return True

    def _guard_api_token(self):
        self.principal = None
        if not urlsplit(self.path).path.startswith("/api/"):
            return True

        values = self.headers.get_all("Authorization", [])
        header = values[0] if len(values) == 1 else ""
        scheme, separator, candidate = header.partition(" ")
        well_formed = (
            len(values) == 1 and bool(separator) and scheme.lower() == "bearer" and bool(candidate)
            and candidate == candidate.strip() and not any(char.isspace() for char in candidate)
            and len(candidate) <= 512
        )
        configured = os.environ.get("MIZAN_JUDGE_TOKEN", "").strip()
        owner_valid = False
        if len(configured.encode("utf-8")) >= 32 and well_formed:
            owner_valid = hmac.compare_digest(
                hashlib.sha256(configured.encode("utf-8")).digest(),
                hashlib.sha256(candidate.encode("utf-8")).digest(),
            )
        if owner_valid:
            self.principal = {
                "id": "installation-owner", "username": "installation-owner", "role": "admin",
                "workspace_id": None, "is_root": True,
            }
            return True

        if well_formed:
            try:
                self.principal = auth_store.authenticate_token(candidate)
            except Exception:
                print("Could not initialize local identity store", file=sys.stderr)
                self._send(503, {"error": "Local identity storage is unavailable."})
                return False
        if self.principal:
            return True

        # A new installation with no owner token and no provisioned users is not ready.
        if len(configured.encode("utf-8")) < 32:
            try:
                if not auth_store.list_users():
                    self._send(503, {"error": "No administrator is configured. Run the local setup command."})
                    return False
            except Exception:
                self._send(503, {"error": "Local identity storage is unavailable."})
                return False
        if self.command in {"POST", "PUT", "PATCH", "DELETE"}:
            self.close_connection = True
        self._send(
            401, {"error": "A valid personal Mizan access token is required."},
            headers={"WWW-Authenticate": 'Bearer realm="Mizan"'},
        )
        return False

    def _require_roles(self, roles):
        if self.principal and self.principal.get("role") in roles:
            return True
        self._send(403, {"error": "Your account does not have permission for this action."})
        return False

    def _workspace_scope(self):
        return None if self.principal.get("is_root") else self.principal.get("workspace_id")

    def _workspace_for_new_case(self, payload):
        if self.principal.get("is_root"):
            value = payload.get("workspace_id", "default")
            if not isinstance(value, str) or not value:
                raise RequestError(400, "Workspace id must be text.")
            return value
        return self.principal["workspace_id"]

    def _actor(self):
        return self.principal["username"], self.principal["id"]

    def _get_user_model_key(self):
        user_id = self.principal["id"]
        key = secret_store.get_user_api_key(user_id)
        if key:
            return key
        # Keep the legacy installation key only for the local installation owner.
        if self.principal.get("is_root"):
            return meta_client.get_config()[0]
        return None

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
        report, code, language = payload.get("report", ""), payload.get("code", ""), payload.get("lang", "en")
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

    def _send_api_error(self, exc, method):
        if isinstance(exc, RequestError):
            self._send(exc.status, {"error": exc.message})
        elif isinstance(exc, review_store.NotFound):
            self._send(404, {"error": "Report not found."})
        elif isinstance(exc, review_store.InvalidState):
            self._send(409, {"error": str(exc)})
        elif isinstance(exc, auth_store.DuplicateUser):
            self._send(409, {"error": str(exc)})
        elif isinstance(exc, auth_store.WorkspaceNotFound):
            self._send(404, {"error": "Workspace not found."})
        elif isinstance(exc, (ValueError, auth_store.AuthStoreError, secret_store.SecretStoreError)):
            self._send(400, {"error": str(exc)})
        elif isinstance(exc, meta_client.MetaAPIError):
            # Upstream 401/403 must not be confused with this user's Mizan token.
            self._send(502, {"error": SAFE_MODEL_ERROR})
        else:
            print("Unhandled local API error in " + method, file=sys.stderr)
            self._send(500, {"error": "Internal server error."})

    def do_GET(self):
        if not self._guard_local_origin() or not self._guard_api_token():
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
            scope = self._workspace_scope()
            if path == "/api/me":
                own_key = secret_store.has_user_api_key(self.principal["id"])
                env_key = bool(self.principal.get("is_root") and meta_client.get_config()[0])
                self._send(200, {
                    "id": self.principal["id"], "username": self.principal["username"],
                    "role": self.principal["role"], "workspace_id": self.principal["workspace_id"],
                    "is_root": self.principal.get("is_root", False), "has_model_key": own_key or env_key,
                })
                return
            if path == "/api/health":
                self._send(200, {"ok": True, "has_key": bool(self._get_user_model_key()), "storage": "local-sqlite"})
                return
            if path == "/api/workspaces":
                workspaces = auth_store.list_workspaces(None if self.principal.get("is_root") else self.principal["workspace_id"])
                self._send(200, {"workspaces": workspaces})
                return
            if path == "/api/admin/users":
                if not self._require_roles({"admin"}):
                    return
                users = auth_store.list_users(None if self.principal.get("is_root") else self.principal["workspace_id"])
                self._send(200, {"users": users})
                return
            if path == "/api/metrics":
                self._send(200, review_store.metrics(workspace_id=scope))
                return
            if path == "/api/sample":
                params = parse_qs(parsed.query, keep_blank_values=True)
                kind, language = params.get("kind", ["valid"])[0], params.get("lang", ["en"])[0]
                if language not in ("en", "ar"):
                    language = "en"
                if kind not in SAMPLE_INPUT:
                    self._send(404, {"error": "Unknown sample."})
                    return
                sample = SAMPLE_INPUT[kind][language]
                self._send(200, sample)
                return
            if path == "/api/reports":
                params = parse_qs(parsed.query, keep_blank_values=True)
                reports = review_store.list_reports(
                    status=params.get("status", [""])[0], query=params.get("q", [""])[0],
                    limit=params.get("limit", [50])[0], offset=params.get("offset", [0])[0], workspace_id=scope,
                )
                self._send(200, {"reports": reports})
                return
            if path.startswith("/api/reports/"):
                report_id, action = self._report_path(path)
                if not report_id:
                    self._send(404, {"error": "Not found."})
                    return
                if action == "history":
                    self._send(200, {"events": review_store.report_history(report_id, workspace_id=scope)})
                elif action is None:
                    self._send(200, {"report": review_store.get_report(report_id, workspace_id=scope)})
                else:
                    self._send(404, {"error": "Not found."})
                return
            self._send(404, {"error": "Not found."})
        except Exception as exc:
            self._send_api_error(exc, "GET")

    def do_POST(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        try:
            payload = self._json_body()
            path = urlsplit(self.path).path
            scope = self._workspace_scope()
            username, actor_id = self._actor()

            if path == "/api/admin/workspaces":
                if not self.principal.get("is_root"):
                    self._send(403, {"error": "Only the installation owner can create workspaces."})
                    return
                name = payload.get("name")
                if not isinstance(name, str):
                    raise RequestError(400, "Workspace name must be text.")
                created = auth_store.create_workspace(name, created_by=username)
                self._send(201, {"workspace": created})
                return
            if path == "/api/admin/users":
                if not self._require_roles({"admin"}):
                    return
                workspace_id = payload.get("workspace_id") or self.principal.get("workspace_id") or "default"
                if not isinstance(workspace_id, str):
                    raise RequestError(400, "Workspace id must be text.")
                if not self.principal.get("is_root") and workspace_id != self.principal["workspace_id"]:
                    self._send(404, {"error": "Workspace not found."})
                    return
                role = payload.get("role", "analyst")
                if not self.principal.get("is_root") and role == "admin":
                    self._send(403, {"error": "Only the installation owner can assign workspace administrator privileges."})
                    return
                user, token = auth_store.create_user(payload.get("username", ""), role, workspace_id, created_by=username)
                self._send(201, {"user": user, "token": token, "token_notice": "Copy this token now; it will not be shown again."})
                return
            if path.startswith("/api/admin/users/") and path.endswith("/rotate-token"):
                if not self._require_roles({"admin"}):
                    return
                user_id = path[len("/api/admin/users/"):-len("/rotate-token")].strip("/")
                if not user_id or user_id == self.principal["id"]:
                    self._send(409, {"error": "Rotate another user's token; the current account cannot rotate itself."})
                    return
                token = auth_store.rotate_user_token(
                    user_id, workspace_id=None if self.principal.get("is_root") else self.principal["workspace_id"]
                )
                if token is None:
                    self._send(404, {"error": "User not found."})
                    return
                self._send(200, {"token": token, "token_notice": "The previous token is revoked. Copy this new token now; it will not be shown again."})
                return
            if path == "/api/triage":
                language = payload.get("lang", "en")
                if not isinstance(language, str) or language not in ("en", "ar"):
                    language = "en"
                demo = payload.get("demo")
                if demo:
                    if not isinstance(demo, str) or demo not in DEMOS:
                        self._send(400, {"error": "Unknown demo."})
                        return
                    sample = SAMPLE_INPUT[demo][language]
                    self._send(200, triage.normalize(DEMOS[demo][language], sample["report"], sample["code"]))
                    return
                if not self._require_roles(ANALYZE_ROLES):
                    return
                if payload.get("confirm_egress") is not True:
                    self._send(400, {"error": "Explicit model-egress confirmation is required."})
                    return
                challenge_pass = payload.get("challenge_pass", False)
                if not isinstance(challenge_pass, bool):
                    self._send(400, {"error": "challenge_pass must be a boolean."})
                    return
                if challenge_pass and payload.get("confirm_challenge_egress") is not True:
                    self._send(400, {"error": "Explicit confirmation for the additional challenge call is required."})
                    return
                report, code, language = self._report_parts(payload)
                api_key = self._get_user_model_key()
                if not api_key:
                    self._send(409, {"error": "Add your own encrypted Meta API key in your account profile before analysis."})
                    return
                self._send(200, triage.triage(report, code, language, api_key=api_key, challenge_pass=challenge_pass))
                return
            if path == "/api/reports":
                if not self._require_roles(ANALYZE_ROLES):
                    return
                report, code, language = self._report_parts(payload)
                workspace_id = self._workspace_for_new_case(payload)
                saved = review_store.create_report(report, code, language, workspace_id=workspace_id, actor=username, actor_user_id=actor_id)
                self._send(201, {"report": saved})
                return
            report_id, action = self._report_path(path)
            if report_id and action == "analyze":
                if not self._require_roles(ANALYZE_ROLES):
                    return
                if payload.get("confirm_egress") is not True:
                    self._send(400, {"error": "Explicit model-egress confirmation is required."})
                    return
                challenge_pass = payload.get("challenge_pass", False)
                if not isinstance(challenge_pass, bool):
                    self._send(400, {"error": "challenge_pass must be a boolean."})
                    return
                if challenge_pass and payload.get("confirm_challenge_egress") is not True:
                    self._send(400, {"error": "Explicit confirmation for the additional challenge call is required."})
                    return
                saved = review_store.get_report(report_id, workspace_id=scope)
                if saved["status"] == "reviewed":
                    raise review_store.InvalidState("A reviewed report cannot be re-analyzed; create a new report instead.")
                api_key = self._get_user_model_key()
                if not api_key:
                    self._send(409, {"error": "Add your own encrypted Meta API key in your account profile before analysis."})
                    return
                analysis = triage.triage(
                    saved["report"], saved["code"], saved["language"],
                    api_key=api_key, challenge_pass=challenge_pass,
                )
                updated = review_store.save_analysis(report_id, analysis, actor=username, workspace_id=scope, actor_user_id=actor_id)
                self._send(200, {"report": updated})
                return
            if report_id and action == "review":
                if not self._require_roles(REVIEW_ROLES):
                    return
                decision, note = payload.get("decision"), payload.get("note", "")
                if not isinstance(decision, str) or not isinstance(note, str):
                    raise RequestError(400, "Decision and note must be text strings.")
                updated = review_store.record_review(
                    report_id, decision, reviewer=username, note=note, workspace_id=scope, actor_user_id=actor_id,
                )
                self._send(200, {"report": updated})
                return
            self._send(404, {"error": "Not found."})
        except Exception as exc:
            self._send_api_error(exc, "POST")

    def do_PUT(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        try:
            payload = self._json_body()
            path = urlsplit(self.path).path
            if path == "/api/me/model-key":
                if not isinstance(payload.get("api_key"), str):
                    raise RequestError(400, "API key must be text.")
                secret_store.set_user_api_key(self.principal["id"], payload["api_key"])
                self._send(200, {"saved": True, "has_model_key": True})
                return
            self._send(405, {"error": "Method not allowed."})
        except Exception as exc:
            self._send_api_error(exc, "PUT")

    def do_DELETE(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        path = urlsplit(self.path).path
        if path == "/api/me/model-key":
            try:
                deleted = secret_store.delete_user_api_key(self.principal["id"])
                self._send(200, {"deleted": deleted, "has_model_key": False})
            except Exception as exc:
                self._send_api_error(exc, "DELETE")
            return
        if path.startswith("/api/admin/users/"):
            if not self._require_roles({"admin"}):
                return
            user_id = path.rsplit("/", 1)[-1]
            if user_id == self.principal["id"]:
                self._send(409, {"error": "You cannot revoke the current token while it is in use."})
                return
            try:
                revoked = auth_store.revoke_user(
                    user_id, workspace_id=None if self.principal.get("is_root") else self.principal["workspace_id"]
                )
            except Exception as exc:
                self._send_api_error(exc, "DELETE")
                return
            self._send(200 if revoked else 404, {"revoked": revoked})
            return
        if not self._require_roles({"admin"}):
            return
        report_id, action = self._report_path(path)
        if not report_id or action is not None:
            self._send(404, {"error": "Not found."})
            return
        try:
            review_store.delete_report(report_id, workspace_id=self._workspace_scope())
            self._send(200, {"deleted": True, "id": report_id})
        except Exception as exc:
            self._send_api_error(exc, "DELETE")

    def do_PATCH(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def do_OPTIONS(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def do_HEAD(self):
        if not self._guard_local_origin() or not self._guard_api_token():
            return
        self._send(405, {"error": "Method not allowed."})

    def log_message(self, fmt, *args):
        # Keep report text, submitted code, tokens, API keys, and provider errors out of routine logs.
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
