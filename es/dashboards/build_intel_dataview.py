"""Standalone Kibana data view for browsing the c2-intel IOC cache.

``c2-intel`` is the abuse.ch feed cache (ThreatFox / URLhaus / Feodo). The reason
job matches it server-side, so it isn't bundled in any dashboard — this ships the
data view on its own for ad-hoc browsing in Discover.

NON-time-based on purpose: the cache is fully replaced each refresh (the
generational purge in intel.py ``_store``) on a ~12h TTL, so a time-based view
with Kibana's default short window would usually show nothing. Browse/filter by
``source`` / ``ioc_type`` / ``value`` / ``host`` / ``malware`` / ``tags``
instead; ``fetched_at`` is still queryable as a plain date field.
"""
import json

# No timeFieldName -> Kibana treats this as a non-time-based data view.
DATA_VIEW = {
    "id": "c2-intel",
    "type": "index-pattern",
    "attributes": {"title": "c2-intel"},
    "references": [],
}

if __name__ == "__main__":
    with open("/tmp/c2-intel.ndjson", "w") as f:
        f.write(json.dumps(DATA_VIEW) + "\n")
    print("wrote /tmp/c2-intel.ndjson")
