"""Generate Kibana 8.19 saved-objects NDJSON for the C2 Entity View (M5).

Surfaces the reason layer's output (`c2-entities`) — escalating `stage`,
`stage_signals`, the family rollup, VT ratios, and counts — which nothing in the
ledger-based Command Center shows. Clicking a `c2_host` pins a filter that drives
both the entity panels AND the ledger drill-down panels (served files / scanners
/ sensors), since `c2_host` is shared — the GreyNoise "callback detail" page.

Self-contained: emits its own data views, so it imports cleanly on a fresh stack.
Agg-based visualizations (stable across Kibana 8.x, unlike hand-authored Lens).
"""
import json

ENTITIES = "c2-entities"  # data view id == index (timeField last_seen)
LEDGER = "c2-ledger"      # data view id (stingarc2-*, timeField ts)
objs = []


def data_view(dv_id, title, time_field):
    objs.append({
        "id": dv_id, "type": "index-pattern",
        "attributes": {"title": title, "timeFieldName": time_field},
        "references": [],
    })


def _ssj(query="", dv=ENTITIES):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def _viz(vid, title, vis, dv=ENTITIES, query=""):
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "uiStateJSON": "{}", "description": "",
            "visState": json.dumps(vis),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query, dv)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": dv}],
    })


def table_viz(vid, title, field, dv=ENTITIES, size=50, query=""):
    _viz(vid, title, {
        "title": title, "type": "table",
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": True, "totalFunc": "sum", "percentageCol": "", "showToolbar": True,
                   "autoFitRowToContent": False},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                        "otherBucket": False, "missingBucket": False}},
        ],
    }, dv, query)


def pie_viz(vid, title, field, dv=ENTITIES, query=""):
    _viz(vid, title, {
        "title": title, "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc", "size": 10,
                        "otherBucket": False, "missingBucket": False}},
        ],
    }, dv, query)


def metric_viz(vid, title, dv=ENTITIES, query=""):
    _viz(vid, title, {
        "title": title, "type": "metric",
        "params": {"metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                              "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                              "labels": {"show": True}, "invertColors": False,
                              "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                        "subText": "", "fontSize": 48}}},
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}],
    }, dv, query)


def markdown_viz(vid, title, md):
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {"title": title, "uiStateJSON": "{}", "description": "",
                       "visState": json.dumps({"title": title, "type": "markdown",
                                               "params": {"markdown": md, "openLinksInNewTab": False, "fontSize": 12},
                                               "aggs": []}),
                       "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj()}},
        "references": [],
    })


def saved_search(sid, title, columns, dv, query=""):
    objs.append({
        "id": sid, "type": "search",
        "attributes": {
            "title": title, "description": "", "columns": columns,
            "sort": [["last_seen", "desc"]] if dv == ENTITIES else [],
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query, dv)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": dv}],
    })


# --- data views (self-contained) ------------------------------------------
data_view(ENTITIES, "c2-entities", "last_seen")
data_view(LEDGER, "stingarc2-*", "ts")

# --- panels ---------------------------------------------------------------
markdown_viz("e-note", "C2 Entities — note",
             "### C2 Entity View\nThe **decaying active-C2 view** (reason-layer "
             "output, ~30 d after last seen). Click a **c2_host** (Active C2 "
             "Entities) → *Filter for value* to pin the **detail page**: the "
             "entity's stage/signals plus the files it served, the scanners "
             "(src_ip) that called it, and the honeypots it hit.\n\n"
             "**Stage**: unconfirmed · stage1_serving · stage2_c2. "
             "**Signals**: callback_in_malware · known_malware · virustotal.")
metric_viz("e-confirmed", "Confirmed C2s (stage2)", query="stage:stage2_c2")
pie_viz("e-stage", "By Stage", "stage")
table_viz("e-signals", "Stage Signals", "stage_signals")
table_viz("e-families", "Families (entity rollup)", "families")
table_viz("e-asn", "Top ASN Orgs", "latest.c2_asn_org")
saved_search("e-entities", "Active C2 Entities",
             ["c2_host", "stage", "stage_signals", "families", "max_evidence_rank",
              "max_vt_ratio", "sighting_count", "sensor_count", "src_ip_count",
              "distinct_files", "latest.c2_asn_org", "last_seen"], ENTITIES)
# --- ledger drill-down (driven by the pinned c2_host filter) --------------
saved_search("e-files", "Served Files (selected C2)",
             ["sha256", "file_kind", "family", "size", "magic", "interpreter", "sensor_hostname"],
             LEDGER, query="evidence:served_file")
table_viz("e-scanners", "Scanners (src_ip)", "src_ip", dv=LEDGER)
table_viz("e-sensors", "Honeypots Hit", "sensor_hostname", dv=LEDGER)

# --- dashboard (48-col grid) ----------------------------------------------
layout = [
    ("e-note",      0,  0, 32, 6,  "visualization"),
    ("e-confirmed", 32, 0, 16, 6,  "visualization"),
    ("e-stage",     0,  6, 16, 11, "visualization"),
    ("e-signals",   16, 6, 16, 11, "visualization"),
    ("e-families",  32, 6, 16, 11, "visualization"),
    ("e-entities",  0, 17, 48, 12, "search"),
    ("e-asn",       0, 29, 16, 11, "visualization"),
    ("e-scanners",  16, 29, 16, 11, "visualization"),
    ("e-sensors",   32, 29, 16, 11, "visualization"),
    ("e-files",     0, 40, 48, 12, "search"),
]
panels, refs = [], []
for i, (oid, x, y, w, h, typ) in enumerate(layout, 1):
    pj = str(i)
    panels.append({"version": "8.19.8", "type": typ,
                   "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pj},
                   "panelIndex": pj, "embeddableConfig": {"enhancements": {}},
                   "panelRefName": f"panel_{pj}"})
    refs.append({"name": f"panel_{pj}", "type": typ, "id": oid})

objs.append({
    "id": "c2-entity-view", "type": "dashboard",
    "attributes": {
        "title": "C2 Entity View",
        "description": "Active, staged C2 entities (reason layer) + per-C2 detail drill-down.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": refs,
})

with open("/tmp/c2-entity-view.ndjson", "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"wrote {len(objs)} saved objects")
