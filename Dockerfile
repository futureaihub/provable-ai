# Zorynex -- Production Dockerfile
# Supports both SQLite (1 worker) and PostgreSQL (N workers).
# Set ZORYNEX_BACKEND=postgres and DATABASE_URL for PostgreSQL mode.
#
# Build:  docker build -t zorynex:latest .
# Run SQLite (dev): docker run -p 8000:8000 zorynex:latest
# Run PG (prod):    docker run -p 8000:8000 -e DATABASE_URL=... \
#                     -e ZORYNEX_BACKEND=postgres \
#                     -e ZORYNEX_WORKERS=4 zorynex:latest

# -- Stage 1: builder ---------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# -- Stage 2: runtime ---------------------------------------------------------
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r zorynex && useradd -r -g zorynex -d /app -s /sbin/nologin zorynex

COPY --from=builder /install /usr/local

WORKDIR /app

COPY provable_ai/ ./provable_ai/
COPY server/      ./server/
COPY migrations/  ./migrations/
COPY alembic.ini  ./

RUN mkdir -p /data && chown zorynex:zorynex /data

USER zorynex

# -- Defaults (override at runtime) -------------------------------------------
ENV ZORYNEX_BACKEND=sqlite \
    ZORYNEX_WORKERS=1 \
    ZORYNEX_DB_PATH=/data/provable_ai.db \
    ZORYNEX_AUDIT_DB_PATH=/data/zorynex_audit.db \
    ZORYNEX_ANCHOR_DB_PATH=/data/zorynex_anchors.db \
    ZORYNEX_KEYREGISTRY_DB_PATH=/data/zorynex_keyregistry.db \
    ZORYNEX_DRIFT_DB_PATH=/data/zorynex_drift.db \
    ZORYNEX_ANCHOR_RFC3161=true \
    ZORYNEX_TSA_URL=https://freetsa.org/tsr \
    ZORYNEX_REQUIRE_TENANT=true \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Worker count:
#   SQLite:     ZORYNEX_WORKERS=1 (single writer, do not increase)
#   PostgreSQL: ZORYNEX_WORKERS=4 (or 2*CPU count -- safe with pg pool)
CMD python3 -m uvicorn server.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers ${ZORYNEX_WORKERS} \
    --no-access-log