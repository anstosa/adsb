"""Regression checks for the privileged deployment boundary."""

import contextlib
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from adsb_admin.controller import (
    alert_status_for,
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
    validate_source_proof,
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
            "resolved_source_dir": "/opt/adsb/releases/test",
            "data_dir": "/var/lib/adsb",
            "activation_id": "a" * 32,
            "tunnel_enabled": False,
            "images": {
                name: "example/image@sha256:" + "a" * 64
                for name in ("ultrafeeder", "piaware", "airspy", "dump978", "proxy", "cloudflared")
            },
            "source_contract_digest": "b" * 64,
            "source_contract": {
                "schema_version": 1,
                "marker_schema_version": 1,
                "source_state_schema_version": 2,
                "aircraft_json_interval_seconds": 1,
                "stats_interval_seconds": 10,
                "sources": {
                    "1090": {
                        "mode": "readsb",
                        "service": "alert-source-1090",
                        "input_service": "airspy",
                        "input_port": 30005,
                        "protocol": "beast_in",
                        "directory": "1090",
                    },
                    "978": {
                        "mode": "readsb",
                        "service": "alert-source-978fallback",
                        "input_service": "dump978",
                        "input_port": 30978,
                        "protocol": "uat_in",
                        "directory": "978",
                    },
                },
            },
        }
        self.absent = {"airspy": False, "uat": False}
        self.present = {"airspy": True, "uat": True}

    # publish a consistent immutable proof fixture without running containers
    def write_source_proof(self, root):
        value = json.loads((Path(__file__).parents[1] / "deploy/alerts/source-proof.json").read_text())
        value["image"] = self.runtime["images"]["ultrafeeder"]
        value["dump978_image"] = self.runtime["images"]["dump978"]
        value["health_sha256"] = hashlib.sha256((root / "deploy/alerts/source-health.sh").read_bytes()).hexdigest()
        value["native978"]["existing_host_http_endpoint"] = "http://127.0.0.1:8978/skyaware978/data/aircraft.json"
        (root / "deploy/alerts/catalog-manifest.json").write_text(
            json.dumps({"entry_count": value["worker"]["catalog_entries"]})
        )
        (root / "deploy/alerts/source-proof.json").write_text(json.dumps(value))

    # reject every omitted or contradicted mandatory g0 evidence section
    def test_source_proof_requires_successful_measured_gate_sections(self):
        root = Path(__file__).parents[1]
        proof = json.loads((root / "deploy/alerts/source-proof.json").read_text())
        images = json.loads((root / "deploy/images.json").read_text())
        health = (root / "deploy/alerts/source-health.sh").read_bytes()
        proof["native978"]["existing_host_http_endpoint"] = "http://127.0.0.1:8978/skyaware978/data/aircraft.json"
        validate_source_proof(proof, images, health, 10684)
        failures = [
            ("sources", None),
            ("native978", None),
            ("worker", None),
            ("production_headroom", None),
            ("dump978_image", "wrong-image"),
            ("sources", proof["sources"][:1]),
        ]
        # refuse omitted or partial aggregate sections
        for key, value in failures:
            invalid = copy.deepcopy(proof)
            invalid[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_source_proof(invalid, images, health, 10684)
        nested_failures = [
            ("worker", "continuity_complete", False),
            ("worker", "provider_dispatches", 1),
            ("worker", "peak_rss_kib", 98304),
            ("worker", "pending_jobs", 1999),
            ("worker", "maintenance_notification_cap", 999),
            ("worker", "maintenance_notifications", 999),
            ("worker", "maintenance_pending", 999),
            ("worker", "maintenance_body_bytes", 8191),
            ("worker", "maintenance_channel", "pushover"),
            ("worker", "maintenance_cap_rejected", False),
            ("production_headroom", "headroom_passed", False),
            ("production_headroom", "oom_events_last_24h", 1),
            ("production_headroom", "vmstat_swap_in_kib_per_second", [0, 1, 0, 0, 0]),
            ("production_headroom", "residual_after_planned_increment_kib", 0),
        ]
        # refuse measurements that contradict the required gate
        for section, key, value in nested_failures:
            invalid = copy.deepcopy(proof)
            invalid[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_source_proof(invalid, images, health, 10684)
        invalid = copy.deepcopy(proof)
        invalid["sources"][0]["readsb_listening_tcp_ports"] = [30005]
        with self.assertRaises(ValueError):
            validate_source_proof(invalid, images, health, 10684)

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
        self.assertEqual(compose["services"]["airspy"]["ports"], ["127.0.0.1:8079:80"])
        self.assertEqual(compose["services"]["dump978"]["ports"], ["127.0.0.1:8978:80"])
        self.assertNotIn("0.0.0.0", str(compose))
        self.assertNotIn("docker.sock", str(compose))
        self.assertNotIn("privileged", str(compose))
        self.assertNotIn("fr24", str(compose))

    # keep each alert tracker isolated to one physical input and no host listener
    def test_alert_sources_use_only_fixed_physical_inputs(self):
        compose = compose_for(self.settings, self.runtime, self.present)
        source_1090 = compose["services"]["alert-source-1090"]
        source_978 = compose["services"]["alert-source-978fallback"]
        self.assertEqual("airspy", source_1090["environment"]["ALERT_SOURCE_INPUT_SERVICE"])
        self.assertEqual("beast_in", source_1090["environment"]["ALERT_SOURCE_PROTOCOL"])
        self.assertEqual("dump978", source_978["environment"]["ALERT_SOURCE_INPUT_SERVICE"])
        self.assertEqual("uat_in", source_978["environment"]["ALERT_SOURCE_PROTOCOL"])
        self.assertNotIn("ports", source_1090)
        self.assertNotIn("ports", source_978)
        self.assertNotIn("mlat", str(source_1090).lower())
        self.assertEqual(["ALL"], source_1090["cap_drop"])
        self.assertTrue(source_1090["read_only"])
        self.assertEqual("64m", source_1090["mem_limit"])

    # reserve receiver startup overhead without weakening input freshness
    def test_alert_source_probes_budget_completion_overhead(self):
        compose = compose_for(self.settings, self.runtime, self.present)
        # keep both physical paths inside the seven-second coverage window
        for name in ("alert-source-1090", "alert-source-978fallback"):
            health = compose["services"][name]["healthcheck"]
            self.assertEqual("1s", health["interval"])
            self.assertEqual("5s", health["timeout"])

    # render no redundant 978 tracker when the reviewed native source is selected
    def test_native_978_selection_omits_fallback_container(self):
        self.runtime["source_contract"]["sources"]["978"] = {
            "mode": "native-dump978",
            "service": "dump978",
            "url": "http://127.0.0.1:8978/skyaware978/data/aircraft.json",
        }
        services = compose_for(self.settings, self.runtime, self.present)["services"]
        self.assertIn("alert-source-1090", services)
        self.assertNotIn("alert-source-978fallback", services)

    # persist graphs and retain no more than thirty days of globe history
    def test_persistent_graphs_and_history_retention_are_configured(self):
        core = compose_for(self.settings, self.runtime, self.present)["services"]["ultrafeeder"]
        environment = core["environment"]
        self.assertEqual("30", environment["MAX_GLOBE_HISTORY"])
        self.assertEqual("true", environment["GRAPHS1090_DARKMODE"])
        self.assertEqual("yes", environment["ENABLE_AIRSPY"])
        self.assertEqual("http://airspy", environment["URL_AIRSPY"])
        self.assertIn("/var/lib/adsb/collectd:/var/lib/collectd", core["volumes"])
        absent_environment = compose_for(self.settings, self.runtime, self.absent)["services"]["ultrafeeder"][
            "environment"
        ]
        self.assertNotIn("ENABLE_AIRSPY", absent_environment)
        self.assertNotIn("URL_AIRSPY", absent_environment)

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
        self.assertEqual(environment["TAR1090_DEFAULTCENTERLAT"], "47.98176459220005")
        self.assertEqual(environment["TAR1090_DEFAULTCENTERLON"], "-122.44336120839758")
        self.assertEqual(environment["TAR1090_DEFAULTZOOMLVL"], "9.802072478907773")

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
        self.assertEqual(core["environment"]["TAR1090_PAGETITLE"], "Ballydídean Farm Sanctuary ADS-B")
        self.assertEqual(core["environment"]["ULTRAFEEDER_CONFIG"], "")

    # keep zero radio traffic distinct from PiAware process failure
    def test_piaware_health_tracks_process_liveness(self):
        self.settings["networks"]["flightaware"]["enabled"] = True
        piaware = compose_for(self.settings, self.runtime, self.present)["services"]["piaware"]
        self.assertEqual(piaware["healthcheck"]["test"], ["CMD-SHELL", "pgrep -x piaware >/dev/null"])
        self.assertEqual(piaware["healthcheck"]["interval"], "10s")
        self.assertNotIn("messages", str(piaware["healthcheck"]))

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

    # keep malformed auxiliary state degraded without touching core uploaders
    def test_malformed_alert_source_state_is_auxiliary_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "alert-source/1090"
            source.mkdir(parents=True)
            (source / "source-state.json").write_text("[" * 1500 + "0" + "]" * 1500)
            services = {
                "running": {"ultrafeeder", "proxy", "airspy", "alert-source-1090"},
                "ready": {"ultrafeeder", "proxy", "airspy", "alert-source-1090"},
                "starting": set(),
            }
            result = alert_status_for(self.runtime, {"airspy": True, "uat": False}, services, root)
        self.assertEqual("degraded", result["sources"]["1090"]["state"])

    # isolate unexpected auxiliary errors and log only their exception class
    def test_alert_projection_failure_is_bounded_and_does_not_stop_core(self):
        with mock.patch("adsb_admin.controller._alert_status_for", side_effect=ValueError("private-token")):
            with mock.patch("adsb_admin.controller.stop_uploaders") as stop:
                with self.assertLogs(level="WARNING") as captured:
                    value = alert_status_for(self.runtime, self.present, {}, Path("/unused"))
        stop.assert_not_called()
        self.assertEqual(["1090", "978"], value["expected_bands"])
        self.assertEqual("degraded", value["sources"]["1090"]["state"])
        self.assertIn("ValueError", str(captured.output))
        self.assertNotIn("private-token", str(captured.output))

    # require fixed socket identity and cumulative bytes in source state
    def test_alert_source_state_includes_socket_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "alert-source/1090"
            source.mkdir(parents=True)
            state = {
                "schema_version": 2,
                "band": "1090",
                "generation": "2de11047-d307-4cce-a43c-4b02958e77c4",
                "activation_id": "a" * 32,
                "contract_digest": "b" * 64,
                "sampled_at": "2026-09-05T00:00:00Z",
                "process_running": True,
                "input_connected": True,
                "input_socket": "123456",
                "input_bytes": 4096,
            }
            (source / "source-state.json").write_text(json.dumps(state), encoding="utf-8")
            services = {
                "running": {"ultrafeeder", "proxy", "airspy", "alert-source-1090"},
                "ready": {"ultrafeeder", "proxy", "airspy", "alert-source-1090"},
                "starting": set(),
            }
            valid = alert_status_for(self.runtime, {"airspy": True, "uat": False}, services, root)
            # reject the older state schema without socket evidence
            state.pop("input_socket")
            state.pop("input_bytes")
            (source / "source-state.json").write_text(json.dumps(state), encoding="utf-8")
            incomplete = alert_status_for(self.runtime, {"airspy": True, "uat": False}, services, root)
        self.assertEqual("ready", valid["sources"]["1090"]["state"])
        self.assertEqual("degraded", incomplete["sources"]["1090"]["state"])

    # catch auxiliary recreation failure inside reconciliation without feed shutdown
    def test_alert_source_recreation_failure_does_not_stop_uploaders(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = dict(self.runtime, data_dir=str(root))
            specification = {
                "name": "adsb",
                "services": {"ultrafeeder": {}, "proxy": {}, "alert-source-1090": {}},
            }
            states = {
                "running": {"ultrafeeder", "proxy"},
                "ready": {"ultrafeeder", "proxy"},
                "starting": set(),
            }
            with mock.patch("sys.argv", ["controller", "--data-dir", str(root), "--once"]):
                with mock.patch("adsb_admin.controller.load_runtime", return_value=runtime):
                    with mock.patch("adsb_admin.controller.read_settings", return_value=self.settings):
                        with mock.patch(
                            "adsb_admin.controller.detect_hardware", return_value={"airspy": True, "uat": False}
                        ):
                            with mock.patch("adsb_admin.controller.compose_for", return_value=specification):
                                with mock.patch("adsb_admin.controller.subprocess.run"):
                                    with mock.patch("adsb_admin.controller.service_states", return_value=states):
                                        with mock.patch("adsb_admin.controller.connector_metrics", return_value=""):
                                            with mock.patch(
                                                "adsb_admin.controller.flightaware_claim_url", return_value=""
                                            ):
                                                with mock.patch(
                                                    "adsb_admin.controller.alert_status_for",
                                                    return_value={"expected_bands": ["1090"]},
                                                ):
                                                    with mock.patch(
                                                        "adsb_admin.controller.recreate_services",
                                                        side_effect=OSError("source unavailable"),
                                                    ):
                                                        with mock.patch(
                                                            "adsb_admin.controller.stop_uploaders"
                                                        ) as stop_uploaders:
                                                            with self.assertLogs(level="ERROR"):
                                                                main()
            stop_uploaders.assert_not_called()

    # steady auxiliary artifact failures must neither recreate nor stop healthy core feeds
    def test_invalid_alert_proof_only_degrades_auxiliary_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy/alerts").mkdir(parents=True)
            (root / "map-ui").mkdir()
            (root / "deploy/nginx.conf").write_text("proxy")
            (root / "map-ui/version.json").write_text("{}")
            (root / "deploy/alerts/source-contract.json").write_text(json.dumps(self.runtime["source_contract"]))
            (root / "deploy/alerts/run-source.sh").write_text("launcher")
            (root / "deploy/alerts/source-health.sh").write_text("health")
            self.write_source_proof(root)
            runtime_path = root / "runtime.json"
            runtime_path.write_text(json.dumps(dict(self.runtime, source_dir=str(root), data_dir=str(root))))
            baseline = load_runtime(runtime_path)
            before = compose_for(self.settings, baseline, self.present)["services"]
            proof_path = root / "deploy/alerts/source-proof.json"
            valid_proof = proof_path.read_bytes()
            states = {
                "running": {"ultrafeeder", "proxy", "airspy", "dump978"},
                "ready": {"ultrafeeder", "proxy", "airspy", "dump978"},
                "starting": set(),
            }
            # exercise absent, deeply malformed, and mismatched evidence independently
            for content in (
                None,
                b"[" * 1500 + b"0" + b"]" * 1500,
                valid_proof.replace(b'"headroom_passed": true', b'"headroom_passed": false'),
            ):
                if content is None:
                    proof_path.unlink(missing_ok=True)
                else:
                    proof_path.write_bytes(content)
                with self.assertRaises((OSError, ValueError, RecursionError)):
                    load_runtime(runtime_path)
                with contextlib.ExitStack() as patches:
                    patches.enter_context(
                        mock.patch(
                            "sys.argv",
                            ["controller", "--runtime", str(runtime_path), "--data-dir", str(root), "--once"],
                        )
                    )
                    patches.enter_context(mock.patch("adsb_admin.controller.read_settings", return_value=self.settings))
                    patches.enter_context(
                        mock.patch("adsb_admin.controller.detect_hardware", return_value=self.present)
                    )
                    patches.enter_context(mock.patch("adsb_admin.controller.subprocess.run", return_value=mock.Mock()))
                    patches.enter_context(mock.patch("adsb_admin.controller.service_states", return_value=states))
                    patches.enter_context(mock.patch("adsb_admin.controller.connector_metrics", return_value=None))
                    patches.enter_context(mock.patch("adsb_admin.controller.ReceptionMonitor.collect", return_value={}))
                    stop = patches.enter_context(mock.patch("adsb_admin.controller.stop_uploaders"))
                    recreate = patches.enter_context(mock.patch("adsb_admin.controller.recreate_services"))
                    patches.enter_context(self.assertLogs(level="WARNING"))
                    main()
                stop.assert_not_called()
                recreate.assert_not_called()
                status = json.loads((root / "status/status.json").read_text())
                self.assertEqual("ready", status["phase"])
                self.assertEqual("degraded", status["alerts"]["sources"]["1090"]["state"])
                after = json.loads((root / "runtime/compose.json").read_text())["services"]
                self.assertEqual(
                    {name: value for name, value in before.items() if not name.startswith("alert-source-")}, after
                )

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
            (root / "deploy/alerts").mkdir()
            (root / "map-ui").mkdir()
            (root / "map-ui/version.json").write_text('{"commit":"first"}')
            configuration = root / "deploy/nginx.conf"
            configuration.write_text("first version")
            (root / "deploy/alerts/source-contract.json").write_text(json.dumps(self.runtime["source_contract"]))
            (root / "deploy/alerts/run-source.sh").write_text("first launcher")
            (root / "deploy/alerts/source-health.sh").write_text("health")
            self.write_source_proof(root)
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

    # include every fixed source contract byte in the recreation identity
    def test_alert_source_script_updates_change_contract_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy/alerts").mkdir(parents=True)
            (root / "map-ui").mkdir()
            (root / "deploy/nginx.conf").write_text("proxy")
            (root / "map-ui/version.json").write_text('{"commit":"first"}')
            (root / "deploy/alerts/source-contract.json").write_text(json.dumps(self.runtime["source_contract"]))
            launcher = root / "deploy/alerts/run-source.sh"
            launcher.write_text("first launcher")
            (root / "deploy/alerts/source-health.sh").write_text("health")
            self.write_source_proof(root)
            runtime_path = root / "runtime.json"
            runtime_path.write_text(json.dumps(dict(self.runtime, source_dir=str(root), data_dir=str(root))))
            first = load_runtime(runtime_path)
            launcher.write_text("second launcher")
            second = load_runtime(runtime_path)
            self.assertNotEqual(first["source_contract_digest"], second["source_contract_digest"])
            proof_path = root / "deploy/alerts/source-proof.json"
            proof = json.loads(proof_path.read_text())
            proof["evidence_note"] = "updated immutable evidence"
            proof_path.write_text(json.dumps(proof))
            third = load_runtime(runtime_path)
            self.assertNotEqual(second["source_contract_digest"], third["source_contract_digest"])
            proof["health_sha256"] = "0" * 64
            proof_path.write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, "selection proof"):
                load_runtime(runtime_path)
            proof_path.unlink()
            with self.assertRaises(FileNotFoundError):
                load_runtime(runtime_path)
            source = compose_for(self.settings, second, {"airspy": True, "uat": False})["services"]["alert-source-1090"]
            self.assertEqual(second["source_contract_digest"], source["labels"]["station.alert-source.contract"])

    # recreate the map container when the pinned asset bundle changes
    def test_map_bundle_updates_change_reconciliation_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "deploy").mkdir()
            (root / "deploy/alerts").mkdir()
            (root / "deploy/nginx.conf").write_text("proxy")
            (root / "map-ui").mkdir()
            version = root / "map-ui/version.json"
            version.write_text('{"commit":"first"}')
            (root / "deploy/alerts/source-contract.json").write_text(json.dumps(self.runtime["source_contract"]))
            (root / "deploy/alerts/run-source.sh").write_text("launcher")
            (root / "deploy/alerts/source-health.sh").write_text("health")
            self.write_source_proof(root)
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
