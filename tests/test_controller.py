"""Regression checks for the privileged deployment boundary."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adsb_admin.controller import (
    compose_for,
    detect_hardware,
    flightaware_claim_url,
    load_runtime,
    log_failure,
    main,
    read_settings,
    recreate_services,
    service_states,
    status_for,
    stop_uploaders,
    tcp_connected,
    validate_settings,
)


# exercise configuration generation without Docker or external feed traffic
class ControllerTests(unittest.TestCase):
    # create a realistic but inert station configuration
    def setUp(self):
        self.settings = {
            "revision": 0,
            "station": {"name": "Test station", "latitude": 48.0, "longitude": -122.0, "altitude_m": 30},
            "networks": {
                name: {"enabled": False, "mlat": False, "feeder_id": "d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43"}
                for name in ("adsbexchange", "flightaware", "adsblol", "airplaneslive")
            },
        }
        self.runtime = {
            "source_dir": "/opt/adsb",
            "data_dir": "/var/lib/adsb",
            "activation_id": "a" * 32,
            "tunnel_enabled": False,
            "images": {
                name: "example/image@sha256:" + "a" * 64
                for name in ("ultrafeeder", "piaware", "airspy", "dump978", "proxy", "cloudflared")
            },
        }
        self.absent = {"airspy": False, "uat": False}
        self.present = {"airspy": True, "uat": True}

    # deny all outbound feeds while no physical receiver is present
    def test_hardware_absence_inhibits_every_network(self):
        # request every feed to exercise the hardware guard
        for network in self.settings["networks"].values():
            network.update(enabled=True, mlat=True)
        compose = compose_for(self.settings, self.runtime, self.absent)
        self.assertEqual(set(compose["services"]), {"ultrafeeder", "proxy"})
        self.assertEqual(compose["services"]["ultrafeeder"]["environment"]["ULTRAFEEDER_CONFIG"], "")

    # remove only the disabled destination and its associated MLAT connector
    def test_toggle_removes_network_and_mlat(self):
        # enable every destination before testing selective shutdown
        for network in self.settings["networks"].values():
            network.update(enabled=True, mlat=True)
        active = compose_for(self.settings, self.runtime, self.present)
        self.assertIn("piaware", active["services"])
        self.settings["networks"]["adsbexchange"]["enabled"] = False
        self.settings["networks"]["flightaware"]["enabled"] = False
        compose = compose_for(self.settings, self.runtime, self.present)
        connectors = compose["services"]["ultrafeeder"]["environment"]["ULTRAFEEDER_CONFIG"]
        self.assertNotIn("adsbexchange.com", connectors)
        self.assertNotIn("piaware", compose["services"])
        self.assertIn("in.adsb.lol", connectors)
        self.assertIn("feed.airplanes.live", connectors)

    # never expose decoder ports or the privileged Docker socket to the web app
    def test_ports_are_loopback_and_no_docker_socket(self):
        compose = compose_for(self.settings, self.runtime, self.present)
        self.assertEqual(compose["services"]["ultrafeeder"]["ports"], ["127.0.0.1:8078:80", "127.0.0.1:9274:9274"])
        self.assertNotIn("docker.sock", str(compose))
        self.assertNotIn("privileged", str(compose))
        self.assertNotIn("fr24", str(compose))

    # treat connector delimiters and malformed coordinates as invalid input
    def test_rejects_injection_and_invalid_shapes(self):
        mutations = [
            lambda value: value["station"].update(name="x;adsb,evil.test,1,beast_out"),
            lambda value: value["station"].update(latitude=float("nan")),
            lambda value: value["station"].update(longitude=True),
            lambda value: value["networks"]["adsblol"].update(feeder_id="x;evil"),
            lambda value: value["networks"]["adsblol"].update(enabled="false"),
            lambda value: value["networks"].update(fr24={}),
            lambda value: value.update(revision=True),
        ]
        # check each malformed input independently
        for mutate in mutations:
            candidate = copy.deepcopy(self.settings)
            mutate(candidate)
            with self.assertRaises(ValueError):
                validate_settings(candidate)

    # do not silently deploy mutable or arbitrary image references
    def test_requires_image_digest(self):
        self.runtime["images"]["ultrafeeder"] = "example/image:latest"
        with self.assertRaises(ValueError):
            compose_for(self.settings, self.runtime, self.absent)

    # do not invent station coordinates on an unconfigured receiver
    def test_unknown_location_is_not_sent_to_decoder(self):
        self.settings["station"].update(latitude=None, longitude=None, altitude_m=None)
        environment = compose_for(self.settings, self.runtime, self.absent)["services"]["ultrafeeder"]["environment"]
        self.assertNotIn("READSB_LAT", environment)
        self.assertNotIn("READSB_LON", environment)
        self.assertNotIn("READSB_ALT", environment)
        self.assertEqual(environment["TAR1090_DEFAULTCENTERLAT"], "39.5")
        self.assertEqual(environment["TAR1090_DEFAULTCENTERLON"], "-98.35")
        self.assertEqual(environment["TAR1090_DEFAULTZOOMLVL"], "4")

    # prevent WebGL's early render from queuing every inactive upstream tile source
    def test_map_defaults_avoid_upstream_tile_starvation(self):
        environment = compose_for(self.settings, self.runtime, self.absent)["services"]["ultrafeeder"]["environment"]
        self.assertEqual(environment["TAR1090_MAPTYPE_TAR1090"], "osm")
        self.assertIn("loStore['webgl'] ??= 'false';", environment["TAR1090_CONFIGJS_APPEND"])

    # serve pinned custom assets without changing receiver data or feed activation
    def test_experimental_map_is_readonly_and_defaults_without_overriding_preferences(self):
        core = compose_for(self.settings, self.runtime, self.absent)["services"]["ultrafeeder"]
        self.assertEqual(core["environment"]["CUSTOM_HTML"], "true")
        self.assertEqual(core["environment"]["UPDATE_TAR1090"], "false")
        self.assertIn("/opt/adsb/map-ui:/var/custom_html:ro", core["volumes"])
        self.assertIn("loStore['ui2_optin'] ??= 'true';", core["environment"]["TAR1090_CONFIGJS_APPEND"])
        self.assertIn("window.matchMedia('(max-width: 767px)').matches", core["environment"]["TAR1090_CONFIGJS_APPEND"])
        self.assertIn("loStore['sidebar_visible'] ??= 'false';", core["environment"]["TAR1090_CONFIGJS_APPEND"])
        self.assertEqual(core["environment"]["ULTRAFEEDER_CONFIG"], "")

    # require complete station coordinates before accepting enabled settings
    def test_enabled_feed_requires_location(self):
        self.settings["station"]["latitude"] = None
        self.settings["networks"]["adsblol"]["enabled"] = True
        with self.assertRaises(ValueError):
            validate_settings(self.settings)

    # parse real hardware IDs without assuming every USB device is a receiver
    def test_detects_supported_radios(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # model the two receivers and an unrelated keyboard
            for name, vendor, product in (("1-1", "1d50", "60a1"), ("2-2", "0bda", "2838"), ("2-3", "413c", "2113")):
                device = root / name
                device.mkdir()
                (device / "idVendor").write_text(vendor)
                (device / "idProduct").write_text(product)
            self.assertEqual(detect_hardware(root), self.present)

    # distinguish successful socket connection from mere configured intent
    def test_connection_metric_requires_positive_age(self):
        self.assertFalse(tcp_connected('readsb_net_connector_status{host="in.adsb.lol",port="30004"} 0', "in.adsb.lol"))
        self.assertTrue(tcp_connected('readsb_net_connector_status{host="in.adsb.lol",port="30004"} 12', "in.adsb.lol"))
        self.assertFalse(tcp_connected('readsb_net_connector_status{host="evil.test",port="30004"} 12', "in.adsb.lol"))

    # report honest waiting status when settings are enabled ahead of hardware
    def test_enabled_without_hardware_is_not_running(self):
        self.settings["networks"]["adsbexchange"]["enabled"] = True
        status = status_for(self.settings, self.absent, {"ultrafeeder", "proxy"}, "", 0)
        self.assertEqual(status["phase"], "waiting")
        self.assertTrue(status["networks"]["adsbexchange"]["enabled"])
        self.assertFalse(status["networks"]["adsbexchange"]["running"])
        self.assertNotIn("feeder_id", str(status))

    # select only unambiguous radio devices and preserve their serial identity
    def test_multiple_radios_are_not_selected_arbitrarily(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # create two RTL receivers with different identities
            for number in (1, 2):
                device = root / str(number)
                device.mkdir()
                (device / "idVendor").write_text("0bda")
                (device / "idProduct").write_text("2838")
                (device / "serial").write_text(f"0000000{number}")
            self.assertFalse(detect_hardware(root)["uat"])

    # isolate UAT relay settings from the 1090 Beast input
    def test_uat_reaches_map_and_flightaware_through_documented_protocol(self):
        self.settings["networks"]["flightaware"]["enabled"] = True
        compose = compose_for(self.settings, self.runtime, self.present)
        environment = compose["services"]["ultrafeeder"]["environment"]
        self.assertIn("adsb,dump978,30978,uat_in", environment["ULTRAFEEDER_CONFIG"])
        self.assertEqual(environment["ENABLE_978"], "yes")
        self.assertEqual(compose["services"]["piaware"]["environment"]["UAT_RECEIVER_TYPE"], "relay")

    # let a clean PiAware cache request an identifier from FlightAware
    def test_new_flightaware_site_bootstraps_without_feeder_id(self):
        self.settings["networks"]["flightaware"].update(enabled=True, feeder_id="")
        compose = compose_for(self.settings, self.runtime, self.present)
        self.assertIn("piaware", compose["services"])
        self.assertNotIn("FEEDER_ID", compose["services"]["piaware"]["environment"])
        validate_settings(self.settings)

    # publish only a validated provider-issued claim destination
    def test_flightaware_claim_url_uses_configured_or_cached_id(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "feeder_id"
            self.assertEqual("", flightaware_claim_url("", cache))
            cache.write_text("not-a-uuid")
            self.assertEqual("", flightaware_claim_url("", cache))
            cached = "d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43"
            cache.write_text(cached + "\n")
            self.assertEqual(
                f"https://www.flightaware.com/adsb/piaware/claim/{cached}",
                flightaware_claim_url("", cache),
            )
            configured = "4d6f9d20-6a0f-45bf-a694-c2e1af158c1d"
            self.assertEqual(
                f"https://www.flightaware.com/adsb/piaware/claim/{configured}",
                flightaware_claim_url(configured, cache),
            )

    # surface the claim link only with a running PiAware process
    def test_flightaware_status_exposes_claim_link(self):
        self.settings["networks"]["flightaware"]["enabled"] = True
        claim_url = "https://www.flightaware.com/adsb/piaware/claim/d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43"
        status = status_for(self.settings, self.present, {"ultrafeeder", "piaware", "proxy"}, "", 1, claim_url)
        self.assertEqual(claim_url, status["networks"]["flightaware"]["claim_url"])

    # bind controller status to the installer activation identity
    def test_status_includes_activation_identity(self):
        status = status_for(self.settings, self.absent, {"ultrafeeder", "proxy"}, "", 1, activation_id="a" * 32)
        self.assertEqual("a" * 32, status["activation_id"])

    # require every instance of a service to be healthy before readiness
    def test_unhealthy_service_is_not_reported_ready(self):
        rows = [
            {"Service": "piaware", "State": "running", "Health": "healthy"},
            {"Service": "piaware", "State": "running", "Health": "unhealthy"},
            {"Service": "proxy", "State": "running", "Health": ""},
        ]
        with mock.patch("adsb_admin.controller.subprocess.run", return_value=mock.Mock(stdout=json.dumps(rows))):
            states = service_states(Path("/runtime/compose.json"))
        self.assertEqual({"piaware", "proxy"}, states["running"])
        self.assertEqual({"proxy"}, states["ready"])
        self.assertEqual(set(), states["starting"])

    # keep starting health checks distinct from ready and failed services
    def test_starting_service_is_not_recreated_or_reported_ready(self):
        rows = [
            {"Service": "piaware", "State": "running", "Health": "starting"},
            {"Service": "proxy", "State": "running", "Health": "healthy"},
        ]
        with mock.patch("adsb_admin.controller.subprocess.run", return_value=mock.Mock(stdout=json.dumps(rows))):
            states = service_states(Path("/runtime/compose.json"))
        self.assertEqual({"piaware", "proxy"}, states["running"])
        self.assertEqual({"proxy"}, states["ready"])
        self.assertEqual({"piaware"}, states["starting"])

    # force-recreate only allowlisted unhealthy services
    def test_recreate_services_is_scoped_to_managed_compose_services(self):
        with mock.patch("adsb_admin.controller.subprocess.run") as run:
            recreate_services(Path("/runtime/compose.json"), {"piaware", "airspy"})
        self.assertEqual(
            [
                "docker",
                "compose",
                "-p",
                "adsb",
                "-f",
                "/runtime/compose.json",
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "airspy",
                "piaware",
            ],
            run.call_args.args[0],
        )
        with self.assertRaises(ValueError):
            recreate_services(Path("/runtime/compose.json"), {"unmanaged"})

    # distinguish missing telemetry from a confirmed disconnected socket
    def test_missing_connection_metrics_remain_unknown(self):
        self.settings["networks"]["adsblol"]["enabled"] = True
        status = status_for(self.settings, self.present, {"ultrafeeder", "proxy"}, None, 1)
        self.assertIsNone(status["networks"]["adsblol"]["connected"])
        self.assertIn("telemetry unavailable", status["networks"]["adsblol"]["message"])

    # reject symlink and oversized settings before root parses their contents
    def test_root_configuration_read_is_bounded_and_no_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "private"
            target.write_text("{}")
            link = root / "settings.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                read_settings(link)
            link.unlink()
            link.write_text(" " * 65537)
            with self.assertRaises(ValueError):
                read_settings(link)

    # stop only this application's uploader containers when applying settings fails
    def test_fail_closed_stops_scoped_uploader_ids(self):
        query = mock.Mock(stdout="0123456789ab\n")
        with mock.patch("adsb_admin.controller.subprocess.run", return_value=query) as run:
            stop_uploaders()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 4)
        self.assertIn("label=com.docker.compose.project=adsb", commands[0])
        self.assertIn("label=com.docker.compose.service=ultrafeeder", commands[0])
        self.assertEqual(commands[1], ["docker", "stop", "--time", "5", "0123456789ab"])
        self.assertIn("label=com.docker.compose.service=piaware", commands[2])

    # attempt the independent FlightAware shutdown even if the main shutdown fails
    def test_fail_closed_attempts_every_uploader_after_first_failure(self):
        failure = subprocess.CalledProcessError(1, ["docker", "ps"], stderr="daemon unavailable")
        with mock.patch("adsb_admin.controller.subprocess.run", side_effect=[failure, mock.Mock(stdout="")]) as run:
            with self.assertLogs(level="ERROR"):
                with self.assertRaises(RuntimeError):
                    stop_uploaders()
        self.assertEqual(run.call_count, 2)
        self.assertIn("label=com.docker.compose.service=piaware", run.call_args_list[1].args[0])

    # root startup errors must trigger the same scoped shutdown as apply errors
    def test_invalid_runtime_fails_closed_at_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime.json"
            runtime.write_text("{")
            with mock.patch("sys.argv", ["controller", "--runtime", str(runtime), "--data-dir", str(root), "--once"]):
                with mock.patch("adsb_admin.controller.stop_uploaders") as stop:
                    with self.assertLogs(level="ERROR"):
                        main()
            stop.assert_called_once()
            status = json.loads((root / "status/status.json").read_text())
            self.assertEqual(status["phase"], "error")

    # include mounted file content in the service identity to force reloads
    def test_proxy_content_updates_change_reconciliation_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy").mkdir()
            (root / "map-ui").mkdir()
            (root / "map-ui/version.json").write_text('{"commit":"first"}')
            configuration = root / "deploy/nginx.conf"
            configuration.write_text("first version")
            runtime_path = root / "runtime.json"
            runtime = dict(self.runtime, source_dir=str(root), data_dir=str(root))
            runtime_path.write_text(json.dumps(runtime))
            first = load_runtime(runtime_path)
            configuration.write_text("second version")
            second = load_runtime(runtime_path)
            self.assertNotEqual(first["proxy_config_digest"], second["proxy_config_digest"])
            proxy = compose_for(self.settings, second, self.absent)["services"]["proxy"]
            self.assertEqual(proxy["cap_drop"], ["ALL"])
            self.assertEqual(proxy["user"], "101:101")

    # recreate the map container when the pinned asset bundle changes
    def test_map_bundle_updates_change_reconciliation_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy").mkdir()
            (root / "deploy/nginx.conf").write_text("proxy")
            (root / "map-ui").mkdir()
            version = root / "map-ui/version.json"
            version.write_text('{"commit":"first"}')
            runtime_path = root / "runtime.json"
            runtime_path.write_text(json.dumps(dict(self.runtime, source_dir=str(root), data_dir=str(root))))
            first = load_runtime(runtime_path)
            version.write_text('{"commit":"second"}')
            second = load_runtime(runtime_path)
            self.assertNotEqual(first["map_ui_digest"], second["map_ui_digest"])
            core = compose_for(self.settings, second, self.absent)["services"]["ultrafeeder"]
            self.assertEqual(core["labels"]["station.map-ui.digest"], second["map_ui_digest"])

    # retain useful diagnostics without retaining a secret identifier
    def test_controller_logs_redact_identifiers_and_secrets(self):
        error = ValueError("uuid=secret-token receiver d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43")
        with self.assertLogs(level="ERROR") as captured:
            log_failure("test", error)
        self.assertNotIn("secret-token", str(captured.output))
        self.assertNotIn("d35c1a7c-63f9-4cb2-a1c0-bfe272e59f43", str(captured.output))
        self.assertIn("ValueError", str(captured.output))


# run the focused regression suite directly or through unittest discovery
if __name__ == "__main__":
    unittest.main()
