FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[geo]'

# Fluent forward in (from central fluentd) — compose-network only.
EXPOSE 24230

ENTRYPOINT ["c2-engine"]
CMD ["serve"]
