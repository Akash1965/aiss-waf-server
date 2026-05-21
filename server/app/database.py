"""SQLAlchemy sync database setup backed by DuckDB.

DuckDB is an embedded columnar OLAP engine — no external server required.
All security events, CVE signatures, and agent records are stored in a single
.duckdb file that can be queried directly with the DuckDB CLI or Python SDK.

Database file location (override with AISS_DATABASE_URL env var):
  Production : duckdb:////data/aiss.duckdb
  Dev/test   : duckdb:///:memory:

DuckDB does not support multiple concurrent write processes on the same file,
so the server runs with a single Uvicorn worker and a shared StaticPool
connection (all threads share one DuckDB connection).

IMPORTANT: All threads share the same DuckDB connection via StaticPool.
DuckDB raises "cannot start a transaction within a transaction" if two threads
try to start a transaction on the same connection concurrently.  A threading
Lock serialises every session acquisition so only one SQLAlchemy session is
active at a time — this is safe and sufficient for a single-host dashboard.
"""

import threading
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool
from app.config import settings
import structlog

log = structlog.get_logger(__name__)

_is_duckdb = "duckdb" in settings.database_url

engine = create_engine(
    settings.database_url,
    echo=settings.environment == "development",
    # StaticPool: all threads share a single in-process DuckDB connection.
    # Required because DuckDB does not allow multiple write connections to
    # the same file from the same process.
    poolclass=StaticPool,
)

SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
)

# Serialize all DB access — DuckDB's single shared connection cannot handle
# concurrent transactions from multiple threads.
_db_lock = threading.Lock()


class Base(DeclarativeBase):
    pass


def _run_migrations() -> None:
    """Apply incremental DDL changes that SQLAlchemy's create_all cannot handle.

    Each migration is wrapped in a try/except so it is silently skipped when
    the column or index already exists (idempotent upgrades).

    Add new migrations at the END of the list — never reorder existing ones.
    """
    migrations = [
        # v1.1 — RBAC: add 'role' column to api_keys
        "ALTER TABLE api_keys ADD COLUMN role VARCHAR(16) DEFAULT 'agent'",
        # v1.2 — Inspect events: ensure all SecurityEvent columns exist
        # (no-ops if the table was freshly created)
    ]
    with engine.begin() as conn:
        for ddl in migrations:
            try:
                conn.execute(text(ddl))
                log.info("Migration applied", ddl=ddl[:60])
            except Exception as exc:
                # Column/index already exists — skip silently
                log.debug("Migration skipped (already applied)", ddl=ddl[:60], exc=str(exc))


async def init_db() -> None:
    """Create all tables on startup, then apply incremental migrations."""
    from app import models  # noqa: F401 — registers models with Base
    Base.metadata.create_all(engine)
    _run_migrations()
    log.info("DuckDB tables initialised", db=settings.database_url)


def get_db() -> Session:
    """FastAPI sync dependency — provides a DB session per request.

    FastAPI runs sync dependencies in a threadpool automatically, so this
    does not block the event loop.  The lock ensures only one session is
    active on the shared DuckDB connection at a time.
    """
    _db_lock.acquire()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        _db_lock.release()
