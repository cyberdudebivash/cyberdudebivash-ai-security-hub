FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# ── Build stage ──────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ── Production stage ─────────────────────────────────────────────────────────
FROM base AS production
WORKDIR /app

# Non-root user for security
RUN useradd -m -u 1001 cdb && chown -R cdb:cdb /app
USER cdb

COPY --from=builder /root/.local /home/cdb/.local
COPY --chown=cdb:cdb . .

ENV PATH="/home/cdb/.local/bin:$PATH"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/v1/health || exit 1

CMD ["uvicorn", "api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "4", "--loop", "uvloop", "--http", "httptools"]
