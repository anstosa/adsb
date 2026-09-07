"""Authentication, sessions, and login throttling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

SCRYPT_PREFIX = "scrypt"
DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60
DEFAULT_LOGIN_WINDOW_SECONDS = 5 * 60
DEFAULT_LOGIN_ATTEMPTS = 5
DEFAULT_MAX_SESSIONS = 1024
DEFAULT_MAX_RATE_LIMIT_CLIENTS = 4096


# represent one authenticated browser
@dataclass(frozen=True)
class Session:
    csrf_token: str
    expires_at: float


# hash a password for secret-file provisioning
def make_password_hash(
    password: str,
    *,
    n: int = 2**14,
    r: int = 8,
    p: int = 1,
    salt: bytes | None = None,
) -> str:
    # reject empty secrets
    if not password:
        raise ValueError("password must not be empty")
    actual_salt = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=actual_salt, n=n, r=r, p=p, dklen=32)
    return "$".join(
        (
            SCRYPT_PREFIX,
            str(n),
            str(r),
            str(p),
            base64.urlsafe_b64encode(actual_salt).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
        )
    )


# decode url-safe base64 without accepting invalid text
def _decode_b64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(value + padding, altchars=b"-_", validate=True)


# parse a provisioned scrypt hash
def parse_password_hash(encoded: str) -> tuple[int, int, int, bytes, bytes]:
    parts = encoded.strip().split("$")
    # require the canonical hash envelope
    if len(parts) != 6 or parts[0] != SCRYPT_PREFIX:
        raise ValueError("password hash must use the scrypt envelope")
    try:
        n, r, p = (int(value) for value in parts[1:4])
        salt = _decode_b64(parts[4])
        expected = _decode_b64(parts[5])
    except (ValueError, TypeError) as exc:
        raise ValueError("password hash is malformed") from exc
    # bound attacker-controlled work factors
    if n < 2**12 or n > 2**17 or n & (n - 1) or r < 1 or r > 32 or p < 1 or p > 16:
        raise ValueError("password hash work factors are unsupported")
    # require meaningful salt and digest sizes
    if len(salt) < 16 or len(expected) != 32:
        raise ValueError("password hash parameters are malformed")
    return n, r, p, salt, expected


# load only a hash from the configured secret source
def load_password_hash(*, value: str | None = None, path: Path | None = None) -> str:
    # reject ambiguous secret sources
    if value is not None and path is not None:
        raise ValueError("configure exactly one password hash source")
    # require one secret source
    if value is None and path is None:
        raise ValueError("configure exactly one password hash source")
    # prefer the direct environment value
    if value is not None:
        encoded = value
    else:
        assert path is not None
        encoded = path.read_text(encoding="utf-8").strip()
    parse_password_hash(encoded)
    return encoded


# compare a submitted password against the stored hash
def verify_password(password: str, encoded: str) -> bool:
    try:
        n, r, p, salt, expected = parse_password_hash(encoded)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
    except (ValueError, UnicodeError):
        return False
    return hmac.compare_digest(actual, expected)


# store short-lived authenticated sessions in process memory
class SessionStore:
    # initialize session storage
    def __init__(
        self,
        ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        clock=time.monotonic,
    ) -> None:
        # require meaningful session bounds
        if ttl_seconds <= 0 or max_sessions <= 0:
            raise ValueError("session bounds must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._clock = clock
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    # remove expired sessions under the active lock
    def _purge_locked(self, now: float) -> None:
        # scan the bounded active-session set
        for token, session in list(self._sessions.items()):
            # discard expired sessions
            if session.expires_at <= now:
                del self._sessions[token]

    # create a new session and csrf secret
    def create(self) -> tuple[str, Session]:
        now = self._clock()
        token = secrets.token_urlsafe(32)
        session = Session(csrf_token=secrets.token_urlsafe(32), expires_at=now + self._ttl_seconds)
        with self._lock:
            self._purge_locked(now)
            # bound memory under repeated successful logins
            if len(self._sessions) >= self._max_sessions:
                self._sessions.pop(next(iter(self._sessions)))
            self._sessions[token] = session
        return token, session

    # retrieve a valid session without extending its lifetime
    def get(self, token: str | None) -> Session | None:
        # reject absent tokens
        if not token:
            return None
        now = self._clock()
        with self._lock:
            self._purge_locked(now)
            return self._sessions.get(token)

    # revoke one session
    def delete(self, token: str | None) -> None:
        # ignore absent tokens
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)


# apply a bounded sliding-window login limit
class LoginRateLimiter:
    # initialize throttle storage
    def __init__(
        self,
        max_attempts: int = DEFAULT_LOGIN_ATTEMPTS,
        window_seconds: int = DEFAULT_LOGIN_WINDOW_SECONDS,
        max_clients: int = DEFAULT_MAX_RATE_LIMIT_CLIENTS,
        clock=time.monotonic,
    ) -> None:
        # require meaningful throttle bounds
        if max_attempts <= 0 or window_seconds <= 0 or max_clients <= 0:
            raise ValueError("rate-limit bounds must be positive")
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._max_clients = max_clients
        self._clock = clock
        self._attempts: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    # trim expired attempts
    def _trim_locked(self, key: str, now: float) -> deque[float]:
        attempts = self._attempts.get(key, deque())
        # remove entries outside the window
        while attempts and attempts[0] <= now - self._window_seconds:
            attempts.popleft()
        # remove empty buckets
        if not attempts:
            self._attempts.pop(key, None)
        return attempts

    # report whether another attempt is allowed
    def allow(self, key: str) -> tuple[bool, int]:
        now = self._clock()
        with self._lock:
            attempts = self._trim_locked(key, now)
            # calculate the remaining wait
            if len(attempts) >= self._max_attempts:
                retry_after = max(1, int(attempts[0] + self._window_seconds - now + 0.999))
                return False, retry_after
            # evict the oldest client bucket at the memory bound
            if key not in self._attempts and len(self._attempts) >= self._max_clients:
                self._attempts.pop(next(iter(self._attempts)))
            self._attempts[key] = attempts
            attempts.append(now)
        return True, 0

    # clear failures after successful authentication
    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


# select a trustworthy client address behind a loopback tunnel
def client_address(peer: str, forwarded: str | None) -> str:
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    # trust cloudflare's address only from the local tunnel
    if peer_ip.is_loopback and forwarded:
        candidate = forwarded.strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return str(peer_ip)
    return str(peer_ip)


# read secret configuration from environment
def password_hash_from_environment() -> str:
    value = os.environ.get("ADSB_ADMIN_PASSWORD_HASH")
    file_value = os.environ.get("ADSB_ADMIN_PASSWORD_HASH_FILE")
    path = Path(file_value) if file_value else None
    return load_password_hash(value=value, path=path)
