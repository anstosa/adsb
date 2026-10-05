"""Provider transport boundary tests without external traffic."""

from __future__ import annotations

import json
import smtplib
import socket
import ssl
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from adsb_admin.alert_delivery import resolve_public_addresses, send_email, send_pushover
from adsb_admin.alert_store import AlertStore


# provide one isolated smtp configuration with an explicit tls mode
def smtp_config(*, port: int = 465) -> dict:
    return {
        "host": "smtp.example.com",
        "port": port,
        "username": "operator",
        "password": "secret",
        "from_address": "alerts@example.com",
        "to_address": "operator@example.net",
    }


# emulate one accepted smtp session
class FakeSMTP:
    # retain submitted messages
    def __init__(self) -> None:
        self.message = None
        self.credentials = None
        self.closed = False

    # accept fixed credentials
    def login(self, username: str, password: str) -> None:
        self.credentials = (username, password)

    # accept one message
    def send_message(self, message):
        self.message = message
        return {}

    # close the session normally
    def quit(self) -> None:
        self.closed = True

    # support failed-quit cleanup
    def close(self) -> None:
        self.closed = True


# lock fixed Pushover semantics
class PushoverDeliveryTest(unittest.TestCase):
    # retry only failures from the explicit pre-request connection phase
    def test_connection_failures_retry_before_any_request_bytes(self) -> None:
        # exercise dns tcp and tls failures at the network boundary
        for error in (socket.gaierror(socket.EAI_AGAIN, "temporary"), ConnectionRefusedError(), ssl.SSLError()):
            with self.subTest(error=type(error).__name__):
                connection = mock.Mock()
                connection.connect.side_effect = error
                connection.request.side_effect = error
                with mock.patch("adsb_admin.alert_delivery.http.client.HTTPSConnection", return_value=connection):
                    result = send_pushover({"app_token": "a", "user_key": "u"}, title="Alert", message="Message")
                self.assertEqual("retry", result.state)
                self.assertEqual("provider_unavailable", result.error_code)
                connection.request.assert_not_called()
                connection.close.assert_called_once()

    # never automatically resend after request transmission becomes uncertain
    def test_request_write_failure_remains_unknown(self) -> None:
        connection = mock.Mock()
        connection.request.side_effect = socket.timeout()
        with mock.patch("adsb_admin.alert_delivery.http.client.HTTPSConnection", return_value=connection):
            result = send_pushover({"app_token": "a", "user_key": "u"}, title="Alert", message="Message")
        self.assertEqual("unknown", result.state)
        self.assertEqual("transport_outcome_unknown", result.error_code)
        connection.close.assert_called_once()

    # convert quota epochs without changing relative retry guidance
    def test_quota_epoch_and_relative_retry_guidance(self) -> None:
        # preserve the provider's separate absolute and relative header semantics
        for headers, expected in (
            ({"x-limit-app-reset": "1010"}, 10),
            ({"retry-after": "15"}, 15),
            ({"x-limit-app-reset": "990"}, 5),
            ({"x-limit-app-reset": "invalid"}, 60),
            ({"x-limit-app-reset": "inf"}, 60),
            ({"x-limit-app-reset": "invalid", "retry-after": "20"}, 20),
            ({"retry-after": "Thu, 01 Jan 1970 00:16:55 GMT"}, 15),
        ):
            with self.subTest(headers=headers), mock.patch("adsb_admin.alert_delivery.time.time", return_value=1000):
                result = send_pushover(
                    {"app_token": "a", "user_key": "u"},
                    title="Alert",
                    message="Message",
                    requester=lambda _body, _timeout: (429, headers, b""),
                )
                self.assertEqual("retry", result.state)
                self.assertEqual(expected, result.retry_after)

    # require normal priority and documented acceptance
    def test_accepts_only_http_200_status_one_at_normal_priority(self) -> None:
        captured = {}

        # accept one in-process provider request
        def requester(body: bytes, timeout: float):
            captured.update(urllib.parse.parse_qs(body.decode("utf-8")))
            self.assertGreater(timeout, 0)
            return 200, {}, json.dumps({"status": 1, "request": "opaque"}).encode("utf-8")

        result = send_pushover(
            {"app_token": "secret-app", "user_key": "secret-user"},
            title="Local aircraft",
            message="Role alert",
            requester=requester,
        )
        self.assertEqual("accepted", result.state)
        self.assertEqual(["0"], captured["priority"])
        self.assertEqual(["secret-app"], captured["token"])

    # distinguish pre-acceptance provider failures and ambiguous transport failures
    def test_retry_failure_and_unknown_outcomes(self) -> None:
        unavailable = send_pushover(
            {"app_token": "a", "user_key": "u"},
            title="Title",
            message="Message",
            requester=lambda _body, _timeout: (503, {}, b""),
        )
        rejected = send_pushover(
            {"app_token": "a", "user_key": "u"},
            title="Title",
            message="Message",
            requester=lambda _body, _timeout: (302, {"location": "https://elsewhere.invalid"}, b""),
        )

        # emulate an ambiguous post-send timeout
        def timeout(_body: bytes, _timeout: float):
            raise socket.timeout()

        unknown = send_pushover(
            {"app_token": "a", "user_key": "u"},
            title="Title",
            message="Message",
            requester=timeout,
        )
        self.assertEqual("retry", unavailable.state)
        self.assertEqual("failed", rejected.state)
        self.assertEqual("unknown", unknown.state)


# lock public-only tls smtp behavior
class EmailDeliveryTest(unittest.TestCase):
    # retain a real durable retry lease after temporary pre-send dns failure
    def test_temporary_dns_failure_remains_retryable_in_the_store(self) -> None:
        # emulate an unavailable resolver without contacting any provider
        def unavailable(_host, _port, **_kwargs):
            raise socket.gaierror(socket.EAI_AGAIN, "temporary")

        result = send_email(
            smtp_config(),
            subject="Alert",
            body="Body",
            message_id="<dns-retry@adsb.ballydidean.farm>",
            resolver=unavailable,
        )
        self.assertEqual("retry", result.state)
        self.assertEqual("smtp_unavailable", result.error_code)
        with tempfile.TemporaryDirectory() as directory:
            store = AlertStore(Path(directory) / "alerts.sqlite3")
            try:
                event_id = store.observe_aircraft(
                    hex_id="A2CCA7",
                    label="News helicopter",
                    categories=("news",),
                    bands={"1090"},
                    required_bands={"1090"},
                    observed_at=100,
                    config_revision=1,
                    enabled=True,
                )
                first = store.claim_deliveries(now=101, config_revision=1, enabled=True, channel="email")[0]
                store.complete_delivery(event_id, "email", result, now=102)
                self.assertEqual([], store.claim_deliveries(now=106, config_revision=1, enabled=True, channel="email"))
                second = store.claim_deliveries(now=107, config_revision=1, enabled=True, channel="email")[0]
                self.assertEqual(first["message_id"], second["message_id"])
                self.assertEqual(2, second["attempt"])
            finally:
                store.close()

    # keep private destinations permanently rejected rather than retrying them
    def test_private_dns_destination_is_still_rejected(self) -> None:
        # return only a loopback destination from the isolated resolver
        def private(_host, _port, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 465))]

        result = send_email(
            smtp_config(),
            subject="Alert",
            body="Body",
            message_id="<private@adsb.ballydidean.farm>",
            resolver=private,
        )
        self.assertEqual("failed", result.state)
        self.assertEqual("smtp_destination_rejected", result.error_code)

    # return one deterministic public dns answer
    @staticmethod
    def public_resolver(_host, _port, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    # reject private, loopback, and mixed dns answers
    def test_resolution_rejects_any_nonpublic_answer(self) -> None:
        # return a rebinding-style mixed answer
        def mixed(_host, _port, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
            ]

        with self.assertRaises(ValueError):
            resolve_public_addresses("smtp.example.com", 465, resolver=mixed)

        # reject resolver amplification before connection attempts
        def too_many(_host, _port, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"93.184.216.{index}", 0)) for index in range(30, 35)]

        with self.assertRaises(ValueError):
            resolve_public_addresses("smtp.example.com", 465, resolver=too_many)

    # accept one message with its stable id and configured destination
    def test_successful_server_acceptance(self) -> None:
        client = FakeSMTP()

        # return the isolated fake session
        def factory(_config, addresses, _context, timeout):
            self.assertEqual(((socket.AF_INET, "93.184.216.34"),), addresses)
            self.assertGreater(timeout, 0)
            return client

        config = smtp_config()
        result = send_email(
            config,
            subject="Local aircraft",
            body="Role alert",
            message_id="<event.email@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=factory,
        )
        self.assertEqual("accepted", result.state)
        self.assertEqual("<event.email@adsb.ballydidean.farm>", client.message["Message-ID"])
        self.assertEqual(("operator", "secret"), client.credentials)
        self.assertTrue(client.closed)

    # mark ambiguous disconnects unknown and authentication failures permanent
    def test_unknown_disconnect_and_permanent_authentication_failure(self) -> None:
        config = smtp_config(port=587)

        # disconnect after a connection may have accepted data
        class DisconnectSMTP(FakeSMTP):
            # emulate an ambiguous send disconnect
            def send_message(self, _message):
                raise smtplib.SMTPServerDisconnected()

        # reject credentials before a message is accepted
        class AuthSMTP(FakeSMTP):
            # emulate documented auth failure
            def login(self, _username: str, _password: str) -> None:
                raise smtplib.SMTPAuthenticationError(535, b"rejected")

        unknown = send_email(
            config,
            subject="Alert",
            body="Body",
            message_id="<one@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=lambda *_args: DisconnectSMTP(),
        )
        failed = send_email(
            config,
            subject="Alert",
            body="Body",
            message_id="<two@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=lambda *_args: AuthSMTP(),
        )
        self.assertEqual("unknown", unknown.state)
        self.assertEqual("failed", failed.state)

    # retry a clearly pre-acceptance temporary smtp response
    def test_temporary_smtp_rejection_is_retryable(self) -> None:
        config = smtp_config()

        # reject data before acceptance with a transient response
        class TemporarySMTP(FakeSMTP):
            # emulate one transient server response
            def send_message(self, _message):
                raise smtplib.SMTPDataError(451, b"try later")

        result = send_email(
            config,
            subject="Alert",
            body="Body",
            message_id="<temporary@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=lambda *_args: TemporarySMTP(),
        )
        self.assertEqual("retry", result.state)
        self.assertGreaterEqual(result.retry_after, 5)

    # distinguish socket failures before and during the mail transaction
    def test_oserror_after_data_is_unknown_but_login_failure_retries(self) -> None:
        config = smtp_config()

        # fail before the mail transaction starts
        class LoginSocketFailure(FakeSMTP):
            # emulate a pre-data socket failure
            def login(self, _username: str, _password: str) -> None:
                raise OSError("disconnected")

        # fail after DATA may have reached the server
        class DataSocketFailure(FakeSMTP):
            # emulate an ambiguous data socket failure
            def send_message(self, _message):
                raise OSError("disconnected")

        retry = send_email(
            config,
            subject="Alert",
            body="Body",
            message_id="<login-failure@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=lambda *_args: LoginSocketFailure(),
        )
        unknown = send_email(
            config,
            subject="Alert",
            body="Body",
            message_id="<data-failure@adsb.ballydidean.farm>",
            resolver=self.public_resolver,
            smtp_factory=lambda *_args: DataSocketFailure(),
        )
        self.assertEqual("retry", retry.state)
        self.assertEqual("unknown", unknown.state)


# run focused checks directly
if __name__ == "__main__":
    unittest.main()
