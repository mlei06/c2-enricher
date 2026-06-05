# Fluentd routing rules for the c2-engine hop

The STINGAR server's fluentd image (`4warned/fluentd`) ships its own config;
these snippets must be merged into it (mount a custom `fluent.conf` over the
stock one — the stock compose has a commented-out volume for exactly this).

Order matters: the engine-hop `<match>` must come BEFORE the stock
catch-all that writes events to Elasticsearch, and the `enriched.*` matches
must route to the SAME ES outputs the stock config uses (same index naming),
so `stingar-*` keeps its existing shape.

See `c2-engine.conf` for the snippets. Milestone 3 validates the merged
config against a dev stack.
