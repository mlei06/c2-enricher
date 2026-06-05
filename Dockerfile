# GeoIP DBs ship in the stock STINGAR fluentd image — reuse them so deploy
# doesn't need a separate host-side maxmind/ directory.
FROM 4warned/fluentd:v2.3 AS geoip

FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[geo]'

COPY --from=geoip /fluentd/etc/GeoLite2-City.mmdb /fluentd/etc/GeoLite2-ASN.mmdb /maxmind/
ENV C2E_MAXMIND_DIR=/maxmind

# Fluent forward in (from central fluentd) — compose-network only.
EXPOSE 24230

ENTRYPOINT ["c2-engine"]
CMD ["serve"]
