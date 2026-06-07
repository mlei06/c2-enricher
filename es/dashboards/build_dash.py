"""Generate Kibana 8.19 saved-objects NDJSON for the C2 Command Center."""
import json

LEDGER = "c2-ledger"      # data view id (stingarc2-*)
SESSIONS = "c2-sessions"  # data view id (stingar-*)
objs = []


def _ssj(query="", filters=None):
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": filters or [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def table_viz(vid, title, field, dv=LEDGER, size=100, query=""):
    vis = {
        "title": title, "type": "table", "params": {
            "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
            "showTotal": True, "totalFunc": "sum", "percentageCol": "", "showToolbar": True,
            "autoFitRowToContent": False,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                "field": field, "orderBy": "1", "order": "desc", "size": size,
                "otherBucket": False, "missingBucket": False,
            }},
        ],
    }
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "uiStateJSON": "{}", "description": "",
            "visState": json.dumps(vis),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": dv}],
    })


def pie_viz(vid, title, field, dv=LEDGER, query=""):
    vis = {
        "title": title, "type": "pie", "params": {
            "type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                "field": field, "orderBy": "1", "order": "desc", "size": 10,
                "otherBucket": False, "missingBucket": False,
            }},
        ],
    }
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {
            "title": title, "uiStateJSON": "{}", "description": "",
            "visState": json.dumps(vis),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": dv}],
    })


def markdown_viz(vid, title, md):
    vis = {"title": title, "type": "markdown",
           "params": {"markdown": md, "openLinksInNewTab": False, "fontSize": 12},
           "aggs": []}
    objs.append({
        "id": vid, "type": "visualization",
        "attributes": {"title": title, "uiStateJSON": "{}", "description": "",
                       "visState": json.dumps(vis),
                       "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj()}},
        "references": [],
    })


def saved_search(sid, title, columns, dv, query=""):
    objs.append({
        "id": sid, "type": "search",
        "attributes": {
            "title": title, "description": "", "columns": columns, "sort": [],
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ssj(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "type": "index-pattern", "id": dv}],
    })


# --- panels ---------------------------------------------------------------
markdown_viz("c2-note", "C2 — note",
             "### C2 Command Center\nClick a **c2_host** (Top C2 Hosts) → "
             "*Filter for value* to pivot every panel: the honeypots it hit, the "
             "src_ips that called it, the payloads it served, and the raw sessions. "
             "Evidence ladder: **0** referenced · **1** served a file · **2** callback in malware.")
table_viz("c2-top-hosts", "C2 — Top C2 Hosts", "c2_host")
pie_viz("c2-evidence", "C2 — Evidence Ladder", "evidence")
table_viz("c2-families", "C2 — Top Threats (family)", "family", query="evidence:served_file")
table_viz("c2-sensors", "C2 — Honeypots Hit", "sensor_hostname")
table_viz("c2-srcips", "C2 — Source IPs", "src_ip")
saved_search("c2-payloads", "C2 — Payloads Served",
             ["c2_host", "file_kind", "family", "sha256", "interpreter", "callbacks",
              "c2_url", "hassh", "sensor_hostname"],
             LEDGER, query="evidence:served_file")
saved_search("c2-sessions-search", "C2 — Raw Sessions",
             ["src_ip", "c2_host", "hp_data.playbook_hash", "hp_data.commands"],
             SESSIONS)

# --- dashboard ------------------------------------------------------------
# grid: 48 cols. Layout rows.
layout = [
    ("c2-note",            0,  0, 48, 4,  "visualization"),
    ("c2-top-hosts",       0,  4, 24, 12, "visualization"),
    ("c2-evidence",       24,  4, 12, 12, "visualization"),
    ("c2-families",       36,  4, 12, 12, "visualization"),
    ("c2-sensors",         0, 16, 16, 10, "visualization"),
    ("c2-srcips",         16, 16, 16, 10, "visualization"),
    ("c2-payloads",       32, 16, 16, 10, "search"),
    ("c2-sessions-search", 0, 26, 48, 12, "search"),
]
panels, refs = [], []
for i, (oid, x, y, w, h, typ) in enumerate(layout, 1):
    pj = str(i)
    panels.append({"version": "8.19.8", "type": typ,
                   "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pj},
                   "panelIndex": pj, "embeddableConfig": {"enhancements": {}},
                   "panelRefName": f"panel_{pj}"})
    refs.append({"name": f"panel_{pj}:panel_{pj}" if False else f"panel_{pj}",
                 "type": typ, "id": oid})

objs.append({
    "id": "c2-command-center", "type": "dashboard",
    "attributes": {
        "title": "C2 Command Center",
        "description": "Surface and pivot on command-and-control infrastructure from honeypot traffic.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": refs,
})

with open("/tmp/c2-dash.ndjson", "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")
print(f"wrote {len(objs)} saved objects")
