"""Reviewed first-visit preferences for the receiver-centered map."""

# retain a display-only fallback until the receiver site is configured
VIEW_DEFAULTS = {
    "CenterLat": "47.98176459220005",
    "CenterLon": "-122.44336120839758",
    "zoomLvl": "9.802072478907773",
}

# omit recent searches, bookmarks and browser bookkeeping from shared defaults
PREFERENCE_DEFAULTS = {
    "MapType_tar1090": "osm",
    "displayUnits": "imperial",
    "MapDim": "false",
    "darkerColors": "false",
    # avoid the pinned build's initial webgl tile starvation
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
    # use the desktop layout after applying the narrow-screen exception
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


# seed only missing storage values before the pinned map initializes
def config_js():
    # serialize only trusted static preference names and string values
    preference_lines = (f"loStore[{key!r}] ??= {value!r};" for key, value in PREFERENCE_DEFAULTS.items())
    return "\n".join(
        (
            "// retain saved centers or let the receiver supply the site position",
            "// use the 5 mi scale at the configured site's latitude unless a zoom is saved",
            f"lopaStore['zoomLvl'] ??= {VIEW_DEFAULTS['zoomLvl']!r};",
            "// enable the upstream session-only tracks default without changing the browser URL",
            "if (!usp.has('allTracks')) {",
            "    usp.params.set('alltracks', '');",
            "}",
            "// keep the map visible on narrow screens unless a sidebar choice is saved",
            "if (window.matchMedia('(max-width: 767px)').matches) {",
            "    loStore['sidebar_visible'] ??= 'false';",
            "}",
            "// fill only absent preferences including empty or false-valued choices",
            *preference_lines,
        )
    )
