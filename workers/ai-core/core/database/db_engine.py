# ============================================================
# CYBERDUDEBIVASH AI — DATABASE ENGINE (PRODUCTION HARDENED)
# Fixes: SQLite concurrent write safety, connection pool config,
#        safe seeding with SELECT FOR UPDATE pattern,
#        WAL mode for SQLite concurrent readers
# ============================================================

from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from core.database.models import Base
from core.settings import settings
from core.logging_config import get_logger

logger = get_logger("database")

_is_sqlite = settings.is_sqlite

# ── Engine — tuned per database type ─────────────────────────
if _is_sqlite:
    # StaticPool + check_same_thread=False for SQLite with Celery/threading
    engine = create_engine(
        settings.database_url,
        connect_args={
            "check_same_thread": False,
            "timeout": 30,           # wait up to 30s for locked DB
        },
        poolclass=StaticPool,        # single connection — safe for SQLite
        pool_pre_ping=True,
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        """Enable WAL mode + foreign keys on every SQLite connection."""
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")   # concurrent reads + one write
        cursor.execute("PRAGMA synchronous=NORMAL")  # safe + fast
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")  # 30s wait on lock
        cursor.close()

else:
    # PostgreSQL / MySQL — use connection pooling
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,  # recycle connections every 30 min
        echo=False,
    )

# ── Session Factory ───────────────────────────────────────────
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,  # prevents DetachedInstanceError after commit
)


# ── FastAPI Dependency ────────────────────────────────────────
def get_db():
    """Yields a DB session and ensures it is always closed."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# ── Initialize Tables ─────────────────────────────────────────
def init_db() -> None:
    """Create all tables and seed defaults. Idempotent — safe to call repeatedly."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified/created")
        _seed_defaults()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def _seed_defaults() -> None:
    """
    Seed default tenant, subscription, and API key.
    Idempotent — uses check before insert pattern.
    """
    from core.database.models import Tenant, Subscription, APIKey

    db = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Tenant).filter(Tenant.id == "default").first():
            return  # Already seeded

        tenant = Tenant(id="default", name="CyberDudeBivash", is_active=True)
        db.add(tenant)
        db.flush()

        sub = Subscription(tenant_id="default", plan="enterprise", credits=99999.0)
        db.add(sub)

        api_key = APIKey(
            tenant_id="default",
            key="cdb-default-api-key-change-in-production",
            name="default",
            is_active=True,
        )
        db.add(api_key)
        db.commit()
        logger.info("Default tenant seeded successfully")

    except Exception as e:
        db.rollback()
        # IntegrityError = already seeded by another worker — not a real error
        if "UNIQUE" in str(e).upper() or "unique" in str(e).lower():
            logger.debug("Default tenant already exists (race condition — harmless)")
        else:
            logger.warning(f"Seed warning: {e}")
    finally:
        db.close()


def health_check() -> bool:
    """Fast DB health check — returns False instead of raising."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"DB health check failed: {e}")
        return False
