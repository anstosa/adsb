"""Threaded local HTTP server for the administration interface."""

from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import posixpath
import re
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .auth import (
    LoginRateLimiter,
    Session,
    SessionStore,
    client_address,
    verify_password,
)
from .config import RevisionConflict, SettingsStore, ValidationError, sanitized_status

MAX_BODY_BYTES = 32 * 1024
SECURE_SESSION_COOKIE_NAME = "__Host-adsb_admin_session"
EMBEDDED_SESSION_COOKIE_NAME = "__Host-adsb_admin_embedded_session"
INSECURE_SESSION_COOKIE_NAME = "adsb_admin_session"
SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)


# normalize one exact trusted embedding origin
def _canonical_frame_origin(value: str) -> str:
    # reject delimiter and header injection before url parsing
    if (
        not value
        or "\\" in value
        or "*" in value
        or "?" in value
        or "#" in value
        or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("frame origin must be one canonical https origin")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("frame origin must be one canonical https origin") from exc
    # require https authority without credentials or non-root paths
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or hostname is None
        or "%" in hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("frame origin must be one canonical https origin")
    # require the default https port
    if port not in (None, 443):
        raise ValueError("frame origin must use the default https port")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            normalized_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("frame origin contains an invalid hostname") from exc
        # require a bounded dns hostname after idna conversion
        if HOSTNAME_PATTERN.fullmatch(normalized_hostname) is None:
            raise ValueError("frame origin contains an invalid hostname")
    else:
        normalized_hostname = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"https://{normalized_hostname}"


# build the frame policy without widening any other source
def _security_policy(frame_origin: str | None) -> str:
    # preserve the standalone deny policy exactly
    if frame_origin is None:
        return SECURITY_POLICY
    return SECURITY_POLICY.replace("frame-ancestors 'none'", f"frame-ancestors {frame_origin}")


# carry authenticated request state
@dataclass(frozen=True)
class AuthContext:
    token: str
    session: Session


# assemble backend dependencies
class AdminApplication:
    # initialize one backend application
    def __init__(
        self,
        *,
        web_root: Path,
        settings_path: Path,
        status_path: Path,
        password_hash: str,
        origin: str,
        secure_cookie: bool = True,
        frame_origin: str | None = None,
        sessions: SessionStore | None = None,
        rate_limiter: LoginRateLimiter | None = None,
    ) -> None:
        normalized_origin = origin.rstrip("/")
        parsed_origin = urlsplit(normalized_origin)
        # require a canonical web origin without a path or credentials
        if (
            parsed_origin.scheme not in ("http", "https")
            or not parsed_origin.netloc
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or parsed_origin.path
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("origin must be an http or https origin")
        # require secure production cookies only on https origins
        if secure_cookie and parsed_origin.scheme != "https":
            raise ValueError("secure cookies require an https origin")
        normalized_frame_origin = None if frame_origin is None else _canonical_frame_origin(frame_origin)
        # require chips security attributes in embedded mode
        if normalized_frame_origin is not None and not secure_cookie:
            raise ValueError("embedded sessions require secure cookies")
        self.web_root = web_root.resolve()
        self.settings = SettingsStore(settings_path)
        self.status_path = status_path
        self.password_hash = password_hash
        self.origin = normalized_origin
        self.secure_cookie = secure_cookie
        self.frame_origin = normalized_frame_origin
        self.security_policy = _security_policy(normalized_frame_origin)
        self.session_cookie_name = (
            EMBEDDED_SESSION_COOKIE_NAME
            if normalized_frame_origin is not None
            else SECURE_SESSION_COOKIE_NAME
            if secure_cookie
            else INSECURE_SESSION_COOKIE_NAME
        )
        self.sessions = sessions or SessionStore()
        self.rate_limiter = rate_limiter or LoginRateLimiter()

    # build matching set and clear cookie attributes
    def session_cookie(self, token: str, *, clear: bool = False) -> str:
        same_site = "None" if self.frame_origin is not None else "Strict"
        attributes = [f"{self.session_cookie_name}={token}", "Path=/", "HttpOnly", f"SameSite={same_site}"]
        # retain the deletion marker only while clearing
        if clear:
            attributes.append("Max-Age=0")
        # bind every production cookie to https
        if self.secure_cookie:
            attributes.append("Secure")
        # partition only the explicitly embedded session
        if self.frame_origin is not None:
            attributes.append("Partitioned")
        return "; ".join(attributes)


# bind application state to a threaded http server
class AdminHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    # initialize the server application
    def __init__(self, address: tuple[str, int], application: AdminApplication) -> None:
        self.application = application
        super().__init__(address, AdminRequestHandler)


# handle the administration http contract
class AdminRequestHandler(BaseHTTPRequestHandler):
    server: AdminHTTPServer
    protocol_version = "HTTP/1.1"

    # suppress sensitive default request logging
    def log_message(self, format_string: str, *args: Any) -> None:
        return

    # add common response protections
    def end_headers(self) -> None:
        application = self.server.application
        self.send_header("Content-Security-Policy", application.security_policy)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # use csp alone for the one configured cross-origin frame parent
        if application.frame_origin is None:
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # describe explicit connection termination
        if self.close_connection:
            self.send_header("Connection", "close")
        super().end_headers()

    # route get requests
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        # expose a minimal unauthenticated liveness probe
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"}, cache=False)
            return
        # expose session state without credentials
        if path == "/api/session":
            auth = self._authentication()
            payload: dict[str, Any] = {"authenticated": auth is not None}
            # provide csrf only to an authenticated browser
            if auth is not None:
                payload["csrf_token"] = auth.session.csrf_token
            self._send_json(HTTPStatus.OK, payload, cache=False)
            return
        # protect configuration reads
        if path == "/api/admin/config":
            # require an authenticated session
            if self._require_authentication() is None:
                return
            self._send_json(HTTPStatus.OK, self.server.application.settings.get_public(), cache=False)
            return
        # protect status reads
        if path == "/api/admin/status":
            # require an authenticated session
            if self._require_authentication() is None:
                return
            self._send_json(HTTPStatus.OK, sanitized_status(self.server.application.status_path), cache=False)
            return
        # reject unknown api routes
        if path.startswith("/api/"):
            self._send_error(HTTPStatus.NOT_FOUND, "not_found")
            return
        # redirect the public root to the map surface
        if path == "/":
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/map/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._serve_static(path, include_body=True)

    # route head requests through safe static handling
    def do_HEAD(self) -> None:
        path = urlsplit(self.path).path
        # allow health head checks
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"}, cache=False, include_body=False)
            return
        # reject api head requests
        if path.startswith("/api/"):
            self._send_error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", include_body=False)
            return
        # redirect the public root to the map surface
        if path == "/":
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/map/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._serve_static(path, include_body=False)

    # route post requests
    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        # accept only same-origin json writes
        if not self._require_write_request():
            return
        # authenticate credentials
        if path == "/api/login":
            self._login()
            return
        # revoke the current session
        if path == "/api/logout":
            auth = self._require_authentication()
            # stop after an authentication response
            if auth is None:
                return
            # require csrf for session mutation
            if not self._require_csrf(auth):
                return
            payload = self._read_json()
            # require an empty json object for logout
            if payload != {}:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, cache=False)
                return
            self.server.application.sessions.delete(auth.token)
            self._send_json(HTTPStatus.OK, {"authenticated": False}, cache=False, clear_cookie=True)
            return
        self.close_connection = True
        self._send_error(HTTPStatus.NOT_FOUND, "not_found")

    # route put requests
    def do_PUT(self) -> None:
        path = urlsplit(self.path).path
        # accept only the configuration route
        if path != "/api/admin/config":
            self.close_connection = True
            self._send_error(HTTPStatus.NOT_FOUND, "not_found")
            return
        # accept only same-origin json writes
        if not self._require_write_request():
            return
        auth = self._require_authentication()
        # stop after an authentication response
        if auth is None:
            return
        # require csrf for settings mutation
        if not self._require_csrf(auth):
            return
        payload = self._read_json()
        # stop after a request-body response
        if payload is None:
            return
        try:
            updated = self.server.application.settings.update(payload)
        except RevisionConflict as exc:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "revision_conflict", "config": exc.current},
                cache=False,
            )
            return
        except ValidationError as exc:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"error": "invalid_request", "fields": exc.fields},
                cache=False,
            )
            return
        self._send_json(HTTPStatus.OK, updated, cache=False)

    # reject unsupported methods
    def do_OPTIONS(self) -> None:
        self._send_error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    # reject unsupported methods
    def do_DELETE(self) -> None:
        self.close_connection = True
        self._send_error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")

    # authenticate a password and establish a session
    def _login(self) -> None:
        app = self.server.application
        address = client_address(self.client_address[0], self.headers.get("CF-Connecting-IP"))
        allowed, retry_after = app.rate_limiter.allow(address)
        # throttle repeated login attempts
        if not allowed:
            self.close_connection = True
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "invalid_credentials"},
                cache=False,
                extra_headers={"Retry-After": str(retry_after)},
            )
            return
        payload = self._read_json()
        # stop after a request-body response
        if payload is None:
            return
        # normalize malformed input before the password check
        valid_shape = (
            isinstance(payload, dict)
            and frozenset(payload) == frozenset(("password",))
            and isinstance(payload.get("password"), str)
            and len(payload["password"]) <= 1024
        )
        candidate = payload["password"] if valid_shape else ""
        authenticated = verify_password(candidate, app.password_hash)
        # return a generic credential failure
        if not valid_shape or not authenticated:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"}, cache=False)
            return
        app.rate_limiter.clear(address)
        old_auth = self._authentication()
        # rotate any existing browser session
        if old_auth is not None:
            app.sessions.delete(old_auth.token)
        token, session = app.sessions.create()
        self._send_json(
            HTTPStatus.OK,
            {"authenticated": True, "csrf_token": session.csrf_token},
            cache=False,
            session_token=token,
        )

    # parse the current browser session
    def _authentication(self) -> AuthContext | None:
        cookie_header = self.headers.get("Cookie")
        # reject absent or oversized cookie input
        if not cookie_header or len(cookie_header) > 4096:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except CookieError:
            return None
        morsel = cookie.get(self.server.application.session_cookie_name)
        # reject missing session cookies
        if morsel is None:
            return None
        token = morsel.value
        session = self.server.application.sessions.get(token)
        # reject unknown or expired sessions
        if session is None:
            return None
        return AuthContext(token=token, session=session)

    # require an authenticated session
    def _require_authentication(self) -> AuthContext | None:
        auth = self._authentication()
        # return a generic authentication response
        if auth is None:
            self.close_connection = True
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"}, cache=False)
            return None
        return auth

    # require a matching csrf request header
    def _require_csrf(self, auth: AuthContext) -> bool:
        supplied = self.headers.get("X-CSRF-Token", "")
        # reject absent or mismatched tokens
        if not supplied or not hmac.compare_digest(supplied, auth.session.csrf_token):
            self.close_connection = True
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "csrf_failed"}, cache=False)
            return False
        return True

    # require strict same-origin json mutation requests
    def _require_write_request(self) -> bool:
        origin = self.headers.get("Origin")
        # require the configured public origin exactly
        if origin != self.server.application.origin:
            self.close_connection = True
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "origin_rejected"}, cache=False)
            return False
        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        # require json to avoid simple cross-site form submissions
        if media_type != "application/json":
            self.close_connection = True
            self._send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"}, cache=False)
            return False
        return True

    # read one bounded json request object
    def _read_json(self) -> Any | None:
        # reject transfer encodings rather than attempting ambiguous framing
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, cache=False)
            return None
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            content_length = -1
        # require a nonempty bounded body
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            self.close_connection = True
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if content_length > MAX_BODY_BYTES else HTTPStatus.BAD_REQUEST
            self._send_json(status, {"error": "invalid_request"}, cache=False)
            return None
        body = self.rfile.read(content_length)
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}, cache=False)
            return None

    # locate and serve a file strictly beneath the configured web root
    def _serve_static(self, request_path: str, *, include_body: bool) -> None:
        try:
            decoded = unquote(request_path, errors="strict")
        except UnicodeDecodeError:
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid_path", include_body=include_body)
            return
        # map the friendly admin route to its document
        if decoded in ("/admin", "/admin/"):
            decoded = "/admin.html"
        normalized = posixpath.normpath(decoded)
        parts = PurePosixPath(decoded).parts
        # reject traversal, alternate separators, and invalid path data
        if ".." in parts or "\\" in decoded or "\x00" in decoded or not decoded.startswith("/"):
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", include_body=include_body)
            return
        relative = normalized.lstrip("/")
        candidate = (self.server.application.web_root / relative).resolve()
        # enforce the static root after symlink resolution
        if self.server.application.web_root not in candidate.parents and candidate != self.server.application.web_root:
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", include_body=include_body)
            return
        # reject directories and missing files
        if not candidate.is_file():
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", include_body=include_body)
            return
        try:
            content = candidate.read_bytes()
        except OSError:
            self._send_error(HTTPStatus.NOT_FOUND, "not_found", include_body=include_body)
            return
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store" if candidate.name == "admin.html" else "public, max-age=300")
        self.end_headers()
        # omit the body for head requests
        if include_body:
            self.wfile.write(content)

    # send a compact json response
    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        *,
        cache: bool,
        include_body: bool = True,
        session_token: str | None = None,
        clear_cookie: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        content = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "private, no-store" if not cache else "private, max-age=30")
        # establish a secure browser session
        if session_token is not None:
            self.send_header("Set-Cookie", self.server.application.session_cookie(session_token))
        # expire a revoked browser session
        if clear_cookie:
            self.send_header("Set-Cookie", self.server.application.session_cookie("", clear=True))
        # add explicitly safe route-specific headers
        if extra_headers:
            # copy each bounded response header
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        # omit the body for head requests
        if include_body:
            self.wfile.write(content)

    # send a consistent json error
    def _send_error(self, status: HTTPStatus, code: str, *, include_body: bool = True) -> None:
        self._send_json(status, {"error": code}, cache=False, include_body=include_body)


# create a configured threaded server
def create_server(address: tuple[str, int], application: AdminApplication) -> AdminHTTPServer:
    return AdminHTTPServer(address, application)
