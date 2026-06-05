# Kibana dashboard exports (milestone 5)

Saved-object exports (`.ndjson`) for the three dashboards specced in
DESIGN.md §7:

1. `c2-command-center.ndjson` — stage overview, active-C2 map, Top Threats,
   Top C2s, evidence-ladder markdown. Default window: last 7d.
2. (Command Center doubles as "C2 Detail" — it is the post-click state of
   the same dashboard, driven by the `c2_host:X` global filter.)
3. `payload-explorer.ndjson` — families over time, distinct-file catalog,
   script source view.

Import: Kibana → Stack Management → Saved Objects → Import.
