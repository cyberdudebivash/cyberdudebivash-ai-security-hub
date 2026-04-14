# ============================================================
# CYBERDUDEBIVASH AI SYSTEM — PRODUCTION DOCKERFILE (HARDENED)
# Multi-stage build, non-root user, minimal attack surface
# ============================================================

FROM python:3.11-slim AS builder

# Build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Non-root user for security
RUN groupadd -r cdbai && useradd -r -g cdbai -s /bin/false cdbai

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=cdbai:cdbai . .

# Create required directories with correct ownership
RUN mkdir -p /app/logs /app/workspace /app/memory /app/data && \
    chown -R cdbai:cdbai /app/logs /app/workspace /app/memory /app/data

# Drop to non-root
USER cdbai

EXPOSE 8000

# Health check at container level
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "generated_app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--log-level", "warning"]
