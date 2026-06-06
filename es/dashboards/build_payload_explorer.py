"""Generate Kibana 8.19 saved-objects NDJSON for the Payload Explorer dashboard.

File-first view over the C2 ledger (served_file rows): what payloads are being
served, by family/over time, one row per distinct sha256, and the script source.
"""
import json

LEDGER = "c2-ledger"  # data view id (stingarc2-*)
SERVED = "evidence:served_file"
objs = []


def _ssj(query=""):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def _viz(vid, title, vis, query=""):
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "uiStateJSON": "{}", "description": "",
            "visState": json.dumps(vis),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": LEDGER}],
    })


def markdown(vid, title, md):
    _viz(vid, title, {"title": title, "type": "markdown",
                      "params": {"markdown": md, "openLinksInNewTab": False, "fontSize": 12},
                      "aggs": []})


def families_over_time(vid, title):
    vis = {"title": title, "type": "histogram", "params": {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                          "show": True, "scale": {"type": "linear"}, "labels": {"show": True},
                          "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                       "position": "left", "show": True, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True}, "title": {"text": "Count"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
    }, "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "ts", "interval": "auto", "useNormalizedEsInterval": True,
                    "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "family", "orderBy": "1", "order": "desc", "size": 10,
                    "otherBucket": False, "missingBucket": False}},
    ]}
    _viz(vid, title, vis, query=SERVED)


def distinct_files_by_family(vid, title):
    vis = {"title": title, "type": "pie", "params": {
        "type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
    }, "aggs": [
        {"id": "1", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "sha256"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": "family", "orderBy": "1", "order": "desc", "size": 10,
                    "otherBucket": False, "missingBucket": False}},
    ]}
    _viz(vid, title, vis, query=SERVED)


def file_catalog(vid, title):
    # one row per distinct sha256, with how widely it spread
    vis = {"title": title, "type": "table", "params": {
        "perPage": 15, "showPartialRows": False, "showMetricsAtAllLevels": False,
        "showTotal": False, "totalFunc": "sum", "percentageCol": "", "showToolbar": True,
    }, "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "4", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "c2_host"}},
        {"id": "5", "enabled": True, "type": "cardinality", "schema": "metric",
         "params": {"field": "sensor_hostname"}},
        {"id": "6", "enabled": True, "type": "max", "schema": "metric", "params": {"field": "ts"}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "sha256", "orderBy": "1", "order": "desc", "size": 100,
                    "otherBucket": False, "missingBucket": False}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "bucket",
         "params": {"field": "family", "orderBy": "1", "order": "desc", "size": 1,
                    "otherBucket": False, "missingBucket": False}},
    ]}
    _viz(vid, title, vis, query=SERVED)


def saved_search(sid, title, columns, query=""):
    objs.append({
        "id": sid, "type": "search",
        "attributes": {"title": title, "description": "", "columns": columns, "sort": [],
                       "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query)}},
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": LEDGER}],
    })


markdown("pe-note", "Payloads — note",
         "### Payload Explorer\nEvery file a C2 served (`evidence:served_file`). "
         "**Click a sha256** in the File Catalog → *Filter for value* to see every "
         "C2 and sensor that served that exact artifact (cross-sensor dedupe). "
         "Script source is the document itself.")
families_over_time("pe-families-time", "Payloads — Families Over Time")
distinct_files_by_family("pe-distinct", "Payloads — Distinct Files by Family")
file_catalog("pe-catalog", "Payloads — File Catalog (per sha256)")
saved_search("pe-script-src", "Payloads — Script Source",
             ["sha256", "c2_host", "interpreter", "size", "content"],
             query="file_kind:script")

layout = [
    ("pe-note",          0,  0, 48, 4,  "visualization"),
    ("pe-families-time", 0,  4, 32, 12, "visualization"),
    ("pe-distinct",     32,  4, 16, 12, "visualization"),
    ("pe-catalog",       0, 16, 48, 14, "visualization"),
    ("pe-script-src",    0, 30, 48, 14, "search"),
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
    "id": "c2-payload-explorer", "type": "dashboard",
    "attributes": {
        "title": "Payload Explorer",
        "description": "File-first view of payloads served by C2s — by family, over time, per sha256.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": refs,
})

with open("/tmp/c2-payload-explorer.ndjson", "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"wrote {len(objs)} saved objects")
