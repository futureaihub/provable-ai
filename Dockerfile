FROM python:3.11-slim

LABEL org.opencontainers.image.title="Zorynex Provable AI"
LABEL org.opencontainers.image.description="Cryptographic proof infrastructure for AI decision governance"
LABEL org.opencontainers.image.url="https://zorynex.co"
LABEL org.opencontainers.image.source="https://github.com/futureaihub/provable-ai"

# Security: run as non-root
RUN groupadd -r zorynex && useradd -r -g zorynex zorynex

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY provable_ai/ ./provable_ai/
COPY server/ ./server/
COPY tools/ ./tools/
COPY cli.py .

# Create data directory for SQLite (pilot mode)
RUN mkdir -p /data && chown zorynex:zorynex /data

USER zorynex

EXPOSE 8000

# Health check — load balancers and orchestrators use this
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
