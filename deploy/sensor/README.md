# Sensor deployment — honeypot host

How to stand up a honeypot sensor and point it at a running STINGAR central
server. A sensor is an **internet-facing host** running enrichment-enabled
Cowrie (`michaeldockerlei/cowrie-stingar`) behind a Fluent Bit forwarder; it
takes attacker traffic on ports 22/23 and ships every session to the central
server, which enriches and stores it. For the server side see
[../server.md](../server.md); for the image internals see
[../../sensor/README.md](../../sensor/README.md).

This guide is **host-agnostic** — any box with a public IP works (a cloud VM,
a VPS, or bare metal). Cloud-specific automation is noted at the end but never
required.

## What you need first

- A host with a **public IP** and root/sudo, reachable from the internet on
  **22/tcp and 23/tcp** (this is the bait — it must be exposed).
- The central server's **FQDN** and its Fluentd port (default `24224`),
  reachable from the host (see *Verify* below — test this early).
- The central stack's **`FLUENTD_KEY`**. It must match exactly or the server
  rejects forwarded events:
  ```bash
  ssh <user>@<central-host> "grep '^FLUENTD_KEY=' ~/stingar/c2-deploy/stingar.env"
  ```
- Docker + the Compose plugin on the host.

## Steps

### 1. Free up port 22 for Cowrie

Cowrie binds host port 22 (and 23) — that's the whole point, attackers expect
SSH there. So **move the box's real management SSH off 22 first**, or you'll
lock yourself out when the honeypot starts. Pick a management port (e.g. 2222):

```bash
echo "Port 2222" | sudo tee /etc/ssh/sshd_config.d/99-mgmt.conf
sudo systemctl restart ssh    # (or sshd)
# reconnect on the new port BEFORE continuing:  ssh -p 2222 <user>@<host>
```

Make sure your firewall (below) allows the management port from your admin IP.

### 2. Get the sensor files

Copy this directory (`deploy/sensor/`) to the host — it has the two files you
need:

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Pulls `cowrie-stingar` + a `fluentbit` forwarder. No build step. |
| `stingar-hp.env.example` | Annotated env template — copy to `stingar-hp.env` and fill it. |

### 3. Configure `stingar-hp.env`

```bash
cp stingar-hp.env.example stingar-hp.env
$EDITOR stingar-hp.env
```

Fill the marked fields:

| Field | Value |
|-------|-------|
| `FLUENTD_HOST` | central server FQDN (matches its `FLUENTD_REMOTE_HOST` / `UI_HOSTNAME`) |
| `FLUENTD_PORT` | central Fluentd port, default `24224` |
| `FLUENTD_KEY` | **must equal** the central stack's `FLUENTD_KEY` (see above) |
| `HONEYPOT_IDENT` | any stable unique id, e.g. `cat /proc/sys/kernel/random/uuid` |
| `HONEYPOT_IP` | the host's **public** IP (not a private/NAT address) |
| `HONEYPOT_HOST` | a name for this sensor (shows in the STINGAR sensor list) |
| `TAGS` | free-form labels, e.g. `network:dmz` |

`stingar-hp.env` holds the shared `FLUENTD_KEY` secret — it is gitignored; keep
it `chmod 600` and off shared logs.

### 4. Open the firewall

On the host firewall **and** any cloud security group / network ACL in front of
it:

| Direction | Port | Source/Dest | Why |
|-----------|------|-------------|-----|
| inbound | `22/tcp`, `23/tcp` | `0.0.0.0/0` | the honeypot bait — must be world-open |
| inbound | your mgmt port (e.g. `2222/tcp`) | your admin IP only | so you can still manage the box |
| outbound | central `FLUENTD_PORT` (`24224`) | central server | so Fluent Bit can forward |

### 5. Start it

```bash
docker compose --env-file stingar-hp.env up -d
```

The image's entrypoint renders `cowrie.cfg` from the env, sends one `sensor`
check-in to the central server, then starts Cowrie. The periodic healthcheck
re-sends the heartbeat so the host stays "alive" in the STINGAR UI.

## Verify

```bash
# 1. Reachability to the central Fluentd (do this even before step 5):
nc -vz <central-fqdn> 24224          # expect: ... port [tcp/*] succeeded!

# 2. Containers up, Cowrie bound to 22/23:
docker compose --env-file stingar-hp.env ps
sudo ss -ltnp | grep -E ':22 |:23 '

# 3. Forwarder healthy (no auth/connection errors):
docker compose --env-file stingar-hp.env logs fluentbit | tail
```

Then confirm the sensor **registered** on the central server — it should appear
in the STINGAR UI sensor list, or via Elasticsearch:

```bash
# on the central host:
docker exec <es-container> curl -s 'localhost:9200/sensors/_search?size=20' \
  | python3 -c 'import sys,json;[print(s["_source"].get("hostname"),s["_source"].get("ip")) for s in json.load(sys.stdin)["hits"]["hits"]]'
```

A real attacker hit (or your own `ssh root@<sensor-public-ip>` with a junk
password) should land in `stingar-*` and roll up into `c2-entities` within a
reason-job pass.

## Operating notes

- **More than one sensor:** repeat with a **unique `HONEYPOT_IDENT` and
  `HONEYPOT_HOST`** per host (everything else, including `FLUENTD_KEY`, is
  shared). Geographic IP diversity is a feature — spread them around.
- **Updating the image:** `docker compose --env-file stingar-hp.env pull && \
  docker compose --env-file stingar-hp.env up -d`.
- **Teardown:** `docker compose --env-file stingar-hp.env down`; then
  decommission the host. The sensor ages out of the STINGAR list once heartbeats
  stop.
- **If c2-engine is down**, the central Fluentd buffers enrichable events and
  retries — sensors keep forwarding; data delays, never drops.

## Automating first-boot (optional, any cloud)

Most clouds let you pass a **first-boot init script** (cloud-init "user-data" or
equivalent). You can automate steps 1–5 there: install Docker, move sshd off 22,
write `stingar-hp.env` (pull `HONEYPOT_IP` from the host's metadata service),
drop in `docker-compose.yml`, and `docker compose up -d`. Two cautions, provider
independent:

- The init script will contain `FLUENTD_KEY` in plaintext and is often readable
  via the instance **metadata service** — restrict metadata access (e.g. limit
  the metadata hop count) so the Cowrie container can't read it back out.
- Keep the management-port firewall rule in the same automation, or a failed
  run can leave you locked out once Cowrie takes port 22.

No cloud is required — the manual steps above are the source of truth.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No events on the server | `nc -vz <central> 24224` from the sensor; firewall egress; `FLUENTD_KEY` matches central exactly |
| Sensor not in the UI list | check-in failed — `FLUENTD_HOST`/port correct? Fluent Bit logs for connection/auth errors |
| Can't SSH after start | you didn't move sshd off 22 (step 1); use the cloud console / mgmt port |
| Cowrie won't start | port 22/23 already in use by the host's own sshd/inetd |
