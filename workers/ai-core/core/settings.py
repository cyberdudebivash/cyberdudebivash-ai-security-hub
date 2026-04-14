# ============================================================
# CYBERDUDEBIVASH AI — CENTRALIZED SETTINGS (HARDENED)
# ============================================================

import os
import sys
import warnings
from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator

_WEAK_SECRET = "CHANGE_ME_IN_PRODUCTION"
_ALLOWED_ENVS = {"development", "staging", "production"}


class Settings(BaseSettings):
    # App
    app_name: str = "CYBERDUDEBIVASH AI SYSTEM"
    app_version: str = "2.0.0"
    app_env: str = Field(default="production", validation_alias="APP_ENV")
    debug: bool = Field(default=False, validation_alias="DEBUG")

    # Security
    secret_key: str = Field(default=_DEFAULT_SECRET_SENTINEL, validation_alias="SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    jwt_expire_hours: int = Field(default=24, validation_alias="JWT_EXPIRE_HOURS")

    # OpenAI
    openai_api_key: str = Field(default="", validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", validation_alias="OPENAI_MODEL")
    openai_max_tokens: int = Field(default=4096)
    openai_temperature: float = Field(default=0.4)
    openai_timeout: int = Field(default=60, validation_alias="OPENAI_TIMEOUT")  # seconds

    # Database
    database_url: str = Field(default="sqlite:///./cdb_ai.db", validation_alias="DATABASE_URL")

    # Redis / Celery
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    celery_concurrency: int = Field(default=4, validation_alias="CELERY_CONCURRENCY")
    celery_task_soft_time_limit: int = Field(default=300, validation_alias="CELERY_TASK_SOFT_TIME_LIMIT")
    celery_task_time_limit: int = Field(default=360, validation_alias="CELERY_TASK_TIME_LIMIT")

    # Rate Limiting
    rate_limit: int = Field(default=100, validation_alias="RATE_LIMIT")
    rate_limit_window: int = Field(default=60, validation_alias="RATE_LIMIT_WINDOW")

    # CORS — restrict in production
    cors_origins: str = Field(default="http://localhost:3000", validation_alias="CORS_ORIGINS")

    # Scheduler
    scheduler_enabled: bool = Field(default=True, validation_alias="SCHEDULER_ENABLED")

    # Cybersecurity
    threat_intel_enabled: bool = Field(default=True, validation_alias="THREAT_INTEL_ENABLED")
    scan_timeout: int = Field(default=30, validation_alias="SCAN_TIMEOUT")
    max_code_audit_chars: int = Field(default=50000)  # ~50KB max code input

    # Stripe
    stripe_secret_key: str = Field(default="", validation_alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str = Field(default="", validation_alias="STRIPE_WEBHOOK_SECRET")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "populate_by_name": True,
    }

    @field_validator("app_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        if v not in _ALLOWED_ENVS:
            raise ValueError(f"APP_ENV must be one of {_ALLOWED_ENVS}, got: {v}")
        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if v == _DEFAULT_SECRET_SENTINEL:
            warnings.warn(
                "SECRET_KEY is using the default insecure value. "
                "Set a strong SECRET_KEY in your .env file before production use.",
                UserWarning,
                stacklevel=2,
            )
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("openai_timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        if v < 10 or v > 300:
            raise ValueError("OPENAI_TIMEOUT must be between 10 and 300 seconds")
        return v

    @property
    def cors_origins_list(self) -> list:
        """Parse CORS_ORIGINS env var into a list."""
        if self.cors_origins == "*":
            return ["*"]
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
