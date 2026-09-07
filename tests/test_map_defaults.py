"""Execute generated map defaults without a receiver or external services."""

import json
import shutil
import subprocess
import unittest

from adsb_admin.config import default_settings
from adsb_admin.controller import compose_for

NODE = shutil.which("node")
VIEW = {
    "zoomLvl": "9.802072478907773",
}
PREFERENCES = {
    "MapType_tar1090": "osm",
    "displayUnits": "imperial",
    "MapDim": "false",
    "darkerColors": "false",
    "webgl": "false",
    "ui2_optin": "true",
    "tableInView": "true",
    "enableLabels": "true",
    "extendedLabels": "1",
    "trackLabels": "false",
    "windLabelsSlim": "true",
    "noVanish": "false",
    "wideInfoblock": "true",
    "planespottingAPI": "false",
    "groundVehicleFilter": "filtered",
    "blockedMLATFilter": "not_filtered",
    "sidebar_visible": "true",
    "sidebar_width": "434",
    "ui2_columnsOpen": "false",
    "sortCol": "altitude",
    "sortAscending": "",
    "layer_nexrad": "true",
    "layer_tfrs": "true",
    "layer_sua": "true",
    "layer_actualRangeOutline": "false",
    "layer_locationDot": "true",
    "layer_siteCircles": "true",
    "layer_noaa_sat": "true",
    "layer_noaa_radar": "false",
    "layer_usa2arefueling": "true",
    "layer_usartccboundaries": "true",
    "column_flight": "false",
    "column_squawk": "false",
    "column_airline": "true",
    "column_track": "false",
    "column_msgs": "false",
    "column_registration": "false",
    "column_type": "true",
    "column_seen": "false",
    "column_sitedist": "false",
    "column_military": "true",
    "column_rssi": "false",
    "column_wd": "false",
    "column_data_source": "false",
}

STORAGE_HARNESS = """
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const loStore = {...input.initial};
const usp = {
    params: new URLSearchParams(input.query),
    // match the upstream case-insensitive parameter lookup
    has(key) { return this.params.has(key.toLowerCase()); }
};
const lopaStore = new Proxy(loStore, {
    // reproduce the pinned map's origin and path namespace
    get(target, key) { return target[input.page + key]; },
    // retain browser string coercion
    set(target, key, value) { target[input.page + key] = String(value); return true; }
});
const window = {
    // exercise both sides of the responsive sidebar rule
    matchMedia(query) {
        // reject accidental changes to the breakpoint contract
        if (query !== '(max-width: 767px)') throw new Error('unexpected media query');
        return {matches: input.narrow};
    }
};
vm.runInNewContext(input.script, {loStore, lopaStore, window, usp});
process.stdout.write(JSON.stringify({storage: loStore, parameters: Object.fromEntries(usp.params)}));
"""


# validate default seeding through the actual controller output
@unittest.skipUnless(NODE, "node is required to execute map-default JavaScript")
class MapDefaultsTests(unittest.TestCase):
    # keep the receiver unconfigured and all uploaders disabled
    def setUp(self):
        self.settings = default_settings()
        self.runtime = {
            "source_dir": "/opt/adsb",
            "data_dir": "/var/lib/adsb",
            "tunnel_enabled": False,
            "images": {
                "ultrafeeder": "example/image@sha256:" + "a" * 64,
                "proxy": "example/image@sha256:" + "b" * 64,
            },
        }

    # evaluate emitted JavaScript against an isolated browser-storage model
    def apply_defaults(self, initial=None, *, narrow=False, page="https://example.test/map/", query=""):
        environment = compose_for(self.settings, self.runtime, {"airspy": False, "uat": False})["services"][
            "ultrafeeder"
        ]["environment"]
        result = subprocess.run(
            [NODE, "-e", STORAGE_HARNESS],
            input=json.dumps(
                {
                    "script": environment["TAR1090_CONFIGJS_APPEND"],
                    "initial": initial or {},
                    "narrow": narrow,
                    "page": page,
                    "query": query,
                }
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return json.loads(result.stdout)

    # copy only reviewed preferences rather than browser history or bookkeeping
    def test_fresh_desktop_gets_exact_reviewed_snapshot(self):
        expected = dict(PREFERENCES)
        # bind the saved view to the page that is actually being visited
        expected.update({"https://example.test/map/" + key: value for key, value in VIEW.items()})
        self.assertEqual(expected, self.apply_defaults()["storage"])

    # hide the imported desktop sidebar only on a fresh narrow browser
    def test_fresh_mobile_keeps_map_visible(self):
        desktop = self.apply_defaults()["storage"]
        mobile = self.apply_defaults(narrow=True)["storage"]
        self.assertEqual({**desktop, "sidebar_visible": "false"}, mobile)

    # preserve saved values including false switches and empty sort direction
    def test_existing_preferences_and_view_are_not_overwritten(self):
        # exercise every reviewed preference rather than only visible switches
        initial = {key: "saved" for key in PREFERENCES}
        # retain each location component independently
        initial.update({"https://example.test/map/" + key: "12" for key in VIEW})
        initial["https://example.test/map/CenterLat"] = "35"
        initial["https://example.test/map/CenterLon"] = "-100"
        initial.update(
            webgl="true",
            ui2_optin="false",
            enableLabels="false",
            noVanish="true",
            tableInView="false",
            groundVehicleFilter="not_filtered",
            extendedLabels="0",
            sortAscending="",
            sidebar_visible="true",
            ui2_recents='{"s":[],"p":[]}',
            LK_RespondToEvents="false",
        )
        self.assertEqual(initial, self.apply_defaults(initial)["storage"])
        self.assertEqual(initial, self.apply_defaults(initial, narrow=True)["storage"])

    # leave other origins and paths alone while filling only missing view values
    def test_view_uses_current_origin_and_path(self):
        page = "http://127.0.0.1:8080/map/"
        initial = {
            page + "CenterLat": "40",
            "https://adsb.ballydidean.farm/map/CenterLon": "-100",
        }
        actual = self.apply_defaults(initial, page=page)["storage"]
        self.assertEqual("40", actual[page + "CenterLat"])
        self.assertNotIn(page + "CenterLon", actual)
        self.assertEqual(VIEW["zoomLvl"], actual[page + "zoomLvl"])
        self.assertEqual("-100", actual["https://adsb.ballydidean.farm/map/CenterLon"])
        self.assertEqual(actual, self.apply_defaults(actual, page=page)["storage"])

    # use the validated site position without overwriting a saved browser center
    def test_station_coordinates_supply_the_initial_center(self):
        self.settings["station"].update(latitude=35, longitude=-100, altitude_m=500)
        environment = compose_for(self.settings, self.runtime, {"airspy": False, "uat": False})["services"][
            "ultrafeeder"
        ]["environment"]
        self.assertEqual("35", environment["READSB_LAT"])
        self.assertEqual("-100", environment["READSB_LON"])
        self.assertEqual("500m", environment["READSB_ALT"])
        actual = self.apply_defaults()["storage"]
        self.assertNotIn("https://example.test/map/CenterLat", actual)
        self.assertNotIn("https://example.test/map/CenterLon", actual)
        self.assertEqual("35", environment["TAR1090_DEFAULTCENTERLAT"])
        self.assertEqual("-100", environment["TAR1090_DEFAULTCENTERLON"])
        self.assertEqual(VIEW["zoomLvl"], environment["TAR1090_DEFAULTZOOMLVL"])

    # preserve valid zero site coordinates rather than treating them as absent
    def test_site_center_accepts_zero_coordinates(self):
        self.settings["station"].update(latitude=0, longitude=0, altitude_m=0)
        environment = compose_for(self.settings, self.runtime, {"airspy": False, "uat": False})["services"][
            "ultrafeeder"
        ]["environment"]
        self.assertEqual("0", environment["TAR1090_DEFAULTCENTERLAT"])
        self.assertEqual("0", environment["TAR1090_DEFAULTCENTERLON"])

    # reuse the upstream startup switch without discarding explicit URL parameters
    def test_all_tracks_startup_preserves_query_overrides(self):
        self.assertEqual({"alltracks": ""}, self.apply_defaults()["parameters"])
        self.assertEqual(
            {"lat": "40", "lon": "-80", "zoom": "7", "alltracks": "1"},
            self.apply_defaults(query="lat=40&lon=-80&zoom=7&alltracks=1")["parameters"],
        )


# support direct execution alongside unittest discovery
if __name__ == "__main__":
    unittest.main()
