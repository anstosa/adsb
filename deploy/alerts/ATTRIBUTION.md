# Aircraft alert catalog attribution

`catalog.json` is a normalized derivative of the pinned
[sdr-enthusiasts/plane-alert-db](https://github.com/sdr-enthusiasts/plane-alert-db/tree/dc611e2cc1c243f61a6d9d913b83613a19e1f858) database.
The upstream database is offered under ODbL 1.0 and individual contents under
DBCL 1.0. The exact upstream and derived digests and transformation rules are
recorded in `catalog-manifest.json`.

The derivative selects exact six-hex ICAO identities whose upstream campaign is
`Mil` or whose category is `Flying Doctors`; malformed upstream identities are
omitted rather than coerced. Four exact news aircraft were reviewed
from explicit news-helicopter rows: A2CCA7, A63954, A7C45A, and ACD27A. The
catalog describes a usual aircraft role; it does not establish an active
military, medical, or news mission.
