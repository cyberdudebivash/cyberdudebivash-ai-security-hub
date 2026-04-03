# Fix #10: generated_app/core is now a proper package
from generated_app.core.celery_app import celery_app
from generated_app.core.redis_client import redis_client

__all__ = ["celery_app", "redis_client"]
