"""Opt-in HTTP regressions against the deployed nginx proxy."""

import http.client
import json
import os
import re
import unittest
from urllib.parse import urlsplit


# require an explicit origin before making live HTTP requests
@unittest.skipUnless(os.environ.get("ADSB_PROXY_TEST_URL"), "set ADSB_PROXY_TEST_URL for live proxy checks")
class ProxyTests(unittest.TestCase):
    # read one public map resource without authentication or settings writes
    def map_resource(self, path):
        origin = urlsplit(os.environ["ADSB_PROXY_TEST_URL"])
        connection_type = {"http": http.client.HTTPConnection, "https": http.client.HTTPSConnection}[origin.scheme]
        connection = connection_type(origin.hostname, origin.port, timeout=10)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            return response.read().decode("utf-8")
        finally:
            connection.close()

    # preserve local receiver data while serving the experimental map by default
    def test_experimental_map_keeps_local_configuration_and_receiver_data(self):
        html = self.map_resource("/map/")
        self.assertRegex(html, r"ui2_[a-f0-9]{32}\.js")
        self.assertRegex(html, r"ui2_[a-f0-9]{32}\.css")
        self.assertRegex(html, r"let databaseFolder = ['\"]db-3\.14\.1715['\"];?")
        early_asset = re.search(r"early_[a-f0-9]{32}\.js", html)
        self.assertIsNotNone(early_asset)
        early = self.map_resource("/map/" + early_asset.group())
        self.assertIn("let aggregator = false;", early)
        self.assertNotIn("let aggregator = true;", early)
        config = self.map_resource("/map/config.js")
        self.assertIn("loStore['ui2_optin'] ??= 'true';", config)
        self.assertIn("loStore['webgl'] ??= 'false';", config)
        self.assertIn("Ballydidean Farm ADS-B", config)
        self.assertIsInstance(json.loads(self.map_resource("/map/data/receiver.json")), dict)
        self.assertIsInstance(json.loads(self.map_resource("/map/data/aircraft.json"))["aircraft"], list)

    # keep tunnel redirects on the caller's public origin
    def test_map_redirects_do_not_expose_the_internal_origin(self):
        origin = urlsplit(os.environ["ADSB_PROXY_TEST_URL"])
        self.assertIn(origin.scheme, ("http", "https"))
        self.assertIsNotNone(origin.hostname)
        connection_type = {"http": http.client.HTTPConnection, "https": http.client.HTTPSConnection}[origin.scheme]
        # cover both nginx-generated map redirects
        for path in ("/", "/map"):
            with self.subTest(path=path):
                connection = connection_type(origin.hostname, origin.port, timeout=10)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 302)
                    self.assertEqual(response.getheader("Location"), "/map/")
                finally:
                    connection.close()
