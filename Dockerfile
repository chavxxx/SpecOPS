# Multi-stage production Dockerfile for SyncHavxxx Security Monitoring Platform
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime image
FROM python:3.11-slim AS runner

WORKDIR /app

# Install runtime utilities (curl for healthchecks, sqlite3 for DB diagnostics)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python dependencies from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Copy application source code
COPY app/ /app/app/
COPY scripts/ /app/scripts/
COPY grafana/ /app/grafana/
COPY run.py /app/run.py
COPY main.py /app/main.py

# Ensure runtime directories exist
RUN mkdir -p /app/data /app/backups /var/log/suricata

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/healthz || exit 1

ENTRYPOINT ["python3", "/app/run.py", "--host", "0.0.0.0", "--port", "8000"]
