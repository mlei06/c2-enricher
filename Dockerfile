# GeoIP DBs ship in the stock STINGAR fluentd image — reuse them so deploy
# doesn't need a separate host-side maxmind/ directory.
FROM 4warned/fluentd:v2.3 AS geoip

FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[geo]'

# In 4warned/fluentd:v2.3 only the ASN db sits in /fluentd/etc; the City db is
# bundled inside the fluent-plugin-geoip gem (verified on the live deployment).
# Glob the gem path so a plugin version bump doesn't break the build.
COPY --from=geoip /fluentd/etc/GeoLite2-ASN.mmdb /maxmind/
COPY --from=geoip /usr/local/bundle/gems/fluent-plugin-geoip-*/data/GeoLite2-City.mmdb /maxmind/
ENV C2E_MAXMIND_DIR=/maxmind
# Unbuffered so logs (incl. tracebacks) flush to `docker logs` immediately.
ENV PYTHONUNBUFFERED=1

# Fluent forward in (from central fluentd) — compose-network only.
EXPOSE 24230

ENTRYPOINT ["c2-engine"]
CMD ["serve"]
