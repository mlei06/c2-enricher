"""Generate the Kibana Maps saved object for the C2 geo layer (M5 remainder).

One Maps object: EMS basemap + a documents layer over ``c2-entities`` placing a
point per active C2 at ``c2_geo`` (the reason job's geo_centroid), fill-colored
by the FINAL ``stage`` (red stage2_c2 / amber stage1_serving / grey unconfirmed).
The entity index decays ~30 d after last_seen, so the map is self-cleaning.

Hand-authored against Kibana 8.19 (LAYER_TYPE GEOJSON_VECTOR / ES_SEARCH source).
Maps descriptors are version-fluid — if this breaks on a Kibana upgrade, re-author
in the Maps UI and re-export (es/dashboards/README.md "Not yet included" note).
Omitted style properties fall back to Maps defaults by design (smaller surface =
fewer schema risks).
"""
import json

ENTITIES = "c2-entities"  # data view id (bundled with c2-entity-view.ndjson)

basemap = {
    "id": "c2geo-base",
    "label": None,
    "minZoom": 0,
    "maxZoom": 24,
    "alpha": 1,
    "visible": True,
    "type": "EMS_VECTOR_TILE",
    "sourceDescriptor": {"type": "EMS_TMS", "isAutoSelect": True,
                         "lightModeDefault": "road_map_desaturated"},
    "style": {"type": "EMS_VECTOR_TILE", "color": ""},
    "includeInFitToBounds": True,
}

points = {
    "id": "c2geo-entities",
    "label": "Active C2 entities",
    "minZoom": 0,
    "maxZoom": 24,
    "alpha": 0.9,
    "visible": True,
    "type": "GEOJSON_VECTOR",
    "joins": [],
    "includeInFitToBounds": True,
    "sourceDescriptor": {
        "id": "c2geo-entities-src",
        "type": "ES_SEARCH",
        "geoField": "c2_geo",
        "indexPatternRefName": "layer_1_source_index_pattern",
        # a handful of points fleet-wide — always show all, no viewport filter
        "filterByMapBounds": False,
        "scalingType": "LIMIT",
        "applyGlobalQuery": True,
        "applyGlobalTime": True,
        "applyForceRefresh": True,
        "sortField": "",
        "sortOrder": "desc",
        "tooltipProperties": ["c2_host", "stage", "stage_signals", "attributed_toolkit",
                              "families", "latest.c2_asn_org", "last_seen"],
        "topHitsGroupByTimeseries": False,
        "topHitsSplitField": "",
        "topHitsSize": 1,
    },
    "style": {
        "type": "VECTOR",
        "isTimeAware": True,
        "properties": {
            "icon": {"type": "STATIC", "options": {"value": "marker"}},
            "symbolizeAs": {"options": {"value": "circle"}},
            "fillColor": {
                "type": "DYNAMIC",
                "options": {
                    "type": "CATEGORICAL",
                    "field": {"name": "stage", "origin": "source"},
                    "colorCategory": "palette_0",
                    "useCustomColorPalette": True,
                    # first entry (stop null) = fallback for unlisted values
                    "customColorPalette": [
                        {"stop": None, "color": "#98A2B3"},
                        {"stop": "stage2_c2", "color": "#BD271E"},
                        {"stop": "stage1_serving", "color": "#FC7B1E"},
                        {"stop": "unconfirmed", "color": "#D3DAE6"},
                    ],
                    "fieldMetaOptions": {"isEnabled": True, "sigma": 3},
                },
            },
            "lineColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
            "lineWidth": {"type": "STATIC", "options": {"size": 1}},
            "iconSize": {"type": "STATIC", "options": {"size": 10}},
        },
    },
}

# Importable by build_entity_view.py, which bundles this object into the
# entity-view ndjson (the dashboard references it as a panel — single-file
# import stays self-contained).
MAP_OBJ = {
    "id": "c2-geo",
    "type": "map",
    "attributes": {
        "title": "C2 — Geo (active C2 infrastructure)",
        "description": ("One point per active C2 (c2-entities, decaying view), "
                        "colored by final stage. Tooltip: host/stage/signals/"
                        "toolkit/families/ASN/last_seen."),
        "layerListJSON": json.dumps([basemap, points]),
        "mapStateJSON": json.dumps({
            "zoom": 1.8,
            "center": {"lon": 15, "lat": 25},
            "timeFilters": {"from": "now-30d", "to": "now"},
            "refreshConfig": {"isPaused": True, "interval": 0},
            "query": {"query": "", "language": "kuery"},
            "filters": [],
        }),
        "uiStateJSON": json.dumps({"isLayerTOCOpen": True, "openTOCDetails": []}),
    },
    "references": [{"name": "layer_1_source_index_pattern",
                    "type": "index-pattern", "id": ENTITIES}],
}

if __name__ == "__main__":
    with open("/tmp/c2-geo-map.ndjson", "w") as f:
        f.write(json.dumps(MAP_OBJ) + "\n")
    print("wrote 1 map saved object")
