# GeoIP DBs ship in the stock STINGAR fluentd image — reuse them so deploy
# doesn't need a separate host-side maxmind/ directory.
FROM 4warned/fluentd:v2.3 AS geoip

FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[geo]'

# In 4warned/fluentd:v2.3 only the ASN db sits in /fluentd/etc — the only City
# db it ships is the fluent-plugin-geoip gem's bundled copy, which is built
# 2017-12-06 and misses post-2017 IP allocations entirely (verified live: both
# real C2 callback IPs were AddressNotFoundError). So take ASN from the fluentd
# image but fetch a CURRENT City db from DB-IP Lite (CC BY 4.0, no license key;
# attribution: IP geolocation by DB-IP, https://db-ip.com). Bump DBIP_MONTH when
# rebuilding much later — old months eventually 404.
ARG DBIP_MONTH=2026-06
COPY --from=geoip /fluentd/etc/GeoLite2-ASN.mmdb /maxmind/
ADD https://download.db-ip.com/free/dbip-city-lite-${DBIP_MONTH}.mmdb.gz /maxmind/dbip-city-lite.mmdb.gz
RUN gunzip /maxmind/dbip-city-lite.mmdb.gz
ENV C2E_MAXMIND_DIR=/maxmind
# Unbuffered so logs (incl. tracebacks) flush to `docker logs` immediately.
ENV PYTHONUNBUFFERED=1

# Fluent forward in (from central fluentd) — compose-network only.
EXPOSE 24230

ENTRYPOINT ["c2-engine"]
CMD ["serve"]
