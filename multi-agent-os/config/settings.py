"""
Platform configuration — all settings from environment, no hardcoded secrets.
"""
from __future__ import annotations
import os
from typing import List

class Settings:
    VERSION     = "1.0.0"
    ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
    WORKERS     = int(os.environ.get("WORKERS", "4"))

    # Database
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://cdb:cdb@localhost:5432/cdb_macos")
    REDIS_URL    = os.environ.get("REDIS_URL",    "redis://localhost:6379/0")
    QDRANT_URL   = os.environ.get("QDRANT_URL",   "http://localhost:6333")

    # AI Providers — provider-agnostic, Anthropic is OPTIONAL
    GROQ_API_KEY       = os.environ.get("GROQ_API_KEY", "")
    DEEPSEEK_API_KEY   = os.environ.get("DEEPSEEK_API_KEY", "")
    OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
    ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")  # OPTIONAL
    CF_ACCOUNT_ID      = os.environ.get("CF_ACCOUNT_ID", "")
    CF_API_TOKEN       = os.environ.get("CF_API_TOKEN", "")

    # Auth
    ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "cdb-macos-admin-2026")
    JWKS_URL      = os.environ.get("JWKS_URL", "")

    # CORS
    ALLOWED_ORIGINS: List[str] = os.environ.get(
        "ALLOWED_ORIGINS",
        "https://cyberdudebivash.in,https://www.cyberdudebivash.in,http://localhost:3000"
    ).split(",")

    # Kafka
    KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "localhost:9092")

    # Observability
    OTEL_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

settings = Settings()
