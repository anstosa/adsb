"""Bounded standard-library Pushover and SMTP delivery."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import smtplib
import socket
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from typing import Any

PUSHOVER_HOST = "api.pushover.net"
PUSHOVER_PATH = "/1/messages.json"
DELIVERY_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class DeliveryResult:
    """Record only safe transport outcome metadata."""

    state: str
    error_code: str | None = None
    retry_after: float | None = None


# identify failures before any provider request could be transmitted
class _PushoverPreSendError(OSError):
    pass


# issue one fixed-origin Pushover request
def _pushover_request(body: bytes, timeout: float) -> tuple[int, dict[str, str], bytes]:
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(PUSHOVER_HOST, 443, timeout=timeout, context=context)
    try:
        try:
            connection.connect()
        except (ssl.SSLError, http.client.HTTPException, OSError) as error:
            # only this explicit connection phase proves safe retry
            raise _PushoverPreSendError("provider connection unavailable") from error
        connection.request(
            "POST",
            PUSHOVER_PATH,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "adsb-alerts/1"},
        )
        response = connection.getresponse()
        content = response.read(MAX_RESPONSE_BYTES + 1)
        # reject oversized provider output without retaining it
        if len(content) > MAX_RESPONSE_BYTES:
            return response.status, {}, b""
        headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, headers, content
    finally:
        connection.close()


# distinguish absolute quota reset dates from relative retry guidance
def _pushover_retry_after(headers: dict[str, str], now: float) -> float:
    # prefer quota reset and fall back to valid standard retry guidance
    for name in ("x-limit-app-reset", "retry-after"):
        raw = headers.get(name)
        try:
            delay = float(raw)
            # quota reset is an epoch rather than a relative interval
            if name == "x-limit-app-reset":
                delay -= now
        except (TypeError, ValueError):
            # only standard retry guidance permits an http date
            if name != "retry-after" or not raw:
                continue
            try:
                stamp = parsedate_to_datetime(raw)
                # a retry date must include an explicit timezone
                if stamp.tzinfo is None:
                    continue
                delay = stamp.timestamp() - now
            except (TypeError, ValueError, OverflowError):
                continue
        # reject nonfinite provider guidance before bounding the retry window
        if math.isfinite(delay):
            return max(5.0, min(delay, 300.0))
    return 60.0


# send one normal-priority Pushover message
def send_pushover(
    config: dict[str, Any],
    *,
    title: str,
    message: str,
    url: str | None = None,
    requester: Callable[[bytes, float], tuple[int, dict[str, str], bytes]] | None = None,
    timeout: float = DELIVERY_TIMEOUT_SECONDS,
) -> DeliveryResult:
    # bound operator-visible text before any network operation
    if not title or len(title) > 250 or not message or len(message) > 1_024:
        return DeliveryResult("failed", "invalid_message")
    form = {
        "token": config.get("app_token", ""),
        "user": config.get("user_key", ""),
        "title": title,
        "message": message,
        "priority": "0",
    }
    # include only a fixed application-generated https link
    if url:
        parsed = urllib.parse.urlsplit(url)
        # reject credentials, fragments, or non-https links
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            return DeliveryResult("failed", "invalid_url")
        form["url"] = url
        form["url_title"] = "Open aircraft map"
    body = urllib.parse.urlencode(form).encode("utf-8")
    actual_requester = requester or _pushover_request
    try:
        status, headers, content = actual_requester(body, timeout)
    except _PushoverPreSendError:
        return DeliveryResult("retry", "provider_unavailable", 5.0)
    except (TimeoutError, socket.timeout, ssl.SSLError, http.client.HTTPException, OSError):
        # network failures after request construction may have been accepted
        return DeliveryResult("unknown", "transport_outcome_unknown")
    # accept only the documented success pair
    if status == 200:
        try:
            payload = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return DeliveryResult("unknown", "invalid_provider_response")
        # require the exact provider success marker
        if isinstance(payload, dict) and payload.get("status") == 1:
            return DeliveryResult("accepted")
        return DeliveryResult("failed", "provider_rejected")
    # honor bounded quota reset guidance
    if status == 429:
        return DeliveryResult("retry", "quota", _pushover_retry_after(headers, time.time()))
    # retry provider failures that are clearly pre-acceptance
    if 500 <= status <= 599:
        return DeliveryResult("retry", "provider_unavailable", 5.0)
    # reject redirects and client failures permanently
    if 300 <= status <= 499:
        return DeliveryResult("failed", "provider_rejected")
    return DeliveryResult("unknown", "invalid_provider_response")


# resolve one hostname and reject every non-public answer
def resolve_public_addresses(
    hostname: str,
    port: int,
    *,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> tuple[tuple[int, str], ...]:
    try:
        results = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError("smtp_dns_failed") from exc
    addresses: list[tuple[int, str]] = []
    # validate each dns answer before connecting
    for family, _socket_type, _protocol, _canonical_name, socket_address in results:
        address = socket_address[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("smtp_dns_invalid") from exc
        # fail closed on private or special-use answers
        if not parsed.is_global:
            raise ValueError("smtp_address_not_public")
        item = (family, address)
        # preserve unique resolver order
        if item not in addresses:
            addresses.append(item)
        # bound connection attempts even under hostile resolver output
        if len(addresses) > 4:
            raise ValueError("smtp_dns_too_many_addresses")
    # require at least one connectable answer
    if not addresses:
        raise ValueError("smtp_dns_empty")
    return tuple(addresses)


# create a connected smtp client against one approved address
def _open_smtp(
    config: dict[str, Any],
    addresses: tuple[tuple[int, str], ...],
    context: ssl.SSLContext,
    timeout: float,
) -> smtplib.SMTP:
    hostname = config["host"]
    port = config["port"]
    last_error: OSError | None = None
    raw_socket: socket.socket | None = None
    deadline = time.monotonic() + timeout
    # attempt only the resolver-approved addresses
    for family, address in addresses:
        candidate: socket.socket | None = None
        try:
            remaining = deadline - time.monotonic()
            # keep the complete address-list connection phase bounded
            if remaining <= 0:
                break
            candidate = socket.socket(family, socket.SOCK_STREAM)
            candidate.settimeout(remaining)
            candidate.connect((address, port))
            candidate.settimeout(timeout)
            raw_socket = candidate
            break
        except OSError as exc:
            last_error = exc
            # close only a successfully allocated socket
            if candidate is not None:
                candidate.close()
    # surface a pre-session connection failure
    if raw_socket is None:
        raise OSError("smtp connect failed") from last_error
    # negotiate implicit tls with original-name sni
    if port == 465:
        client: smtplib.SMTP = smtplib.SMTP_SSL(timeout=timeout, context=context)
        client._host = hostname
        client.sock = context.wrap_socket(raw_socket, server_hostname=hostname)
        code, _message = client.getreply()
        # require a valid smtp greeting
        if code != 220:
            client.close()
            raise smtplib.SMTPConnectError(code, b"invalid greeting")
        client.ehlo_or_helo_if_needed()
        return client
    client = smtplib.SMTP(timeout=timeout)
    client._host = hostname
    client.sock = raw_socket
    code, _message = client.getreply()
    # require a valid smtp greeting
    if code != 220:
        client.close()
        raise smtplib.SMTPConnectError(code, b"invalid greeting")
    client.ehlo()
    # refuse plaintext fallback
    if not client.has_extn("starttls"):
        client.close()
        raise ssl.SSLError("smtp STARTTLS is required")
    client.starttls(context=context)
    client.ehlo()
    return client


# send one tls-protected email
def send_email(
    config: dict[str, Any],
    *,
    subject: str,
    body: str,
    message_id: str,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
    smtp_factory: Callable[[dict[str, Any], tuple[tuple[int, str], ...], ssl.SSLContext, float], Any] | None = None,
    timeout: float = DELIVERY_TIMEOUT_SECONDS,
) -> DeliveryResult:
    # reject unsafe message headers before resolution
    if (
        not subject
        or len(subject) > 200
        or "\r" in subject
        or "\n" in subject
        or not message_id.startswith("<")
        or not message_id.endswith(">")
        or "\r" in message_id
        or "\n" in message_id
    ):
        return DeliveryResult("failed", "invalid_message")
    try:
        addresses = resolve_public_addresses(config["host"], config["port"], resolver=resolver)
    except OSError:
        return DeliveryResult("retry", "smtp_unavailable", 5.0)
    except (KeyError, ValueError):
        return DeliveryResult("failed", "smtp_destination_rejected")
    message = EmailMessage()
    message["From"] = config["from_address"]
    message["To"] = config["to_address"]
    message["Subject"] = subject
    message["Message-ID"] = message_id
    message.set_content(body)
    context = ssl.create_default_context()
    factory = smtp_factory or _open_smtp
    client: Any = None
    may_have_sent = False
    try:
        client = factory(config, addresses, context, timeout)
        client.login(config["username"], config["password"])
        may_have_sent = True
        refused = client.send_message(message)
        # treat any refused recipient as a permanent failure
        if refused:
            return DeliveryResult("failed", "smtp_recipient_refused")
        return DeliveryResult("accepted")
    except smtplib.SMTPAuthenticationError:
        return DeliveryResult("failed", "smtp_authentication_failed")
    except (ssl.CertificateError, ssl.SSLError):
        return DeliveryResult("failed", "smtp_tls_failed")
    except smtplib.SMTPRecipientsRefused as exc:
        codes = [value[0] for value in exc.recipients.values() if isinstance(value, tuple) and value]
        # retry only an entirely transient recipient refusal
        if codes and all(400 <= code <= 499 for code in codes):
            return DeliveryResult("retry", "smtp_temporarily_rejected", 5.0)
        return DeliveryResult("failed", "smtp_recipient_refused")
    except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
        # retry documented transient smtp response codes before acceptance
        if 400 <= exc.smtp_code <= 499:
            return DeliveryResult("retry", "smtp_temporarily_rejected", 5.0)
        return DeliveryResult("failed", "smtp_rejected")
    except (TimeoutError, socket.timeout, smtplib.SMTPServerDisconnected):
        # distinguish failures before DATA from possibly accepted messages
        if may_have_sent:
            return DeliveryResult("unknown", "transport_outcome_unknown")
        return DeliveryResult("retry", "smtp_unavailable", 5.0)
    except (smtplib.SMTPConnectError, smtplib.SMTPHeloError):
        return DeliveryResult("retry", "smtp_unavailable", 5.0)
    except OSError:
        # generic socket failures during DATA have ambiguous acceptance
        if may_have_sent:
            return DeliveryResult("unknown", "transport_outcome_unknown")
        return DeliveryResult("retry", "smtp_unavailable", 5.0)
    except smtplib.SMTPException:
        return DeliveryResult("failed", "smtp_rejected")
    finally:
        # close without masking the recorded delivery outcome
        if client is not None:
            try:
                client.quit()
            except (OSError, smtplib.SMTPException):
                client.close()
