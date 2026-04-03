# ============================================================
# CYBERDUDEBIVASH AI — CELERY APP (PRODUCTION HARDENED)
# Fixes: task timeouts, exponential backoff on retries,
#        persistent beat schedule path, proper serialization
# ============================================================

import os
from celery import Celery
from celery.schedules import crontab
from kombu import Queue

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "cdb_ai",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "generated_app.tasks.ai_tasks",
        "generated_app.tasks.cyber_tasks",
        "generated_app.tasks.scheduler_tasks",
        "generated_app.tasks.toolgen_tasks",
    ],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,

    # HARD TIMEOUT: prevents zombie workers from stalled AI calls
    task_soft_time_limit=int(os.getenv("CELERY_TASK_SOFT_TIME_LIMIT", 300)),
    task_time_limit=int(os.getenv("CELERY_TASK_TIME_LIMIT", 360)),

    # Performance — prefetch 1 prevents one slow task from blocking others
    worker_concurrency=int(os.getenv("CELERY_CONCURRENCY", 4)),
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,  # restart worker after 100 tasks — prevents memory leaks

    # Explicit queues with priorities
    task_queues=(
        Queue("ai_tasks",    routing_key="ai_tasks"),
        Queue("cyber_tasks", routing_key="cyber_tasks"),
        Queue("default",     routing_key="default"),
    ),
    task_default_queue="default",
    task_routes={
        "generated_app.tasks.ai_tasks.*":        {"queue": "ai_tasks"},
        "generated_app.tasks.cyber_tasks.*":     {"queue": "cyber_tasks"},
        "generated_app.tasks.scheduler_tasks.*": {"queue": "default"},
    },

    # Result expiry — don't keep results forever
    result_expires=3600,

    # Retry policy — exponential backoff
    task_annotations={
        "*": {
            "rate_limit": "60/m",
        }
    },

    # Beat schedule — autonomous workflows
    beat_schedule={
        "threat-intel-sweep": {
            "task": "generated_app.tasks.scheduler_tasks.scheduled_threat_sweep",
            "schedule": crontab(minute=0, hour="*/4"),
        },
        "system-health-check": {
            "task": "generated_app.tasks.scheduler_tasks.scheduled_health_check",
            "schedule": crontab(minute="*/15"),
        },
        "memory-cleanup": {
            "task": "generated_app.tasks.scheduler_tasks.scheduled_memory_cleanup",
            "schedule": crontab(hour=0, minute=0),
        },
        "auto-threat-toolgen": {
            "task": "generated_app.tasks.toolgen_tasks.scheduled_threat_toolgen",
            "schedule": crontab(minute=30, hour="*/6"),  # every 6 hours
        },
    },

    # Beat schedule DB path — persistent and explicit
    beat_schedule_filename=os.path.join(
        os.getenv("MEMORY_DIR", "memory"), "celerybeat-schedule"
    ),

    # Broker connection resilience
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    broker_transport_options={
        "visibility_timeout": 3600,
        "max_retries": 5,
        "interval_start": 0,
        "interval_step": 1,
        "interval_max": 10,
    },
    result_backend_transport_options={
        "retry_policy": {
            "timeout": 5.0,
        }
    },
)
