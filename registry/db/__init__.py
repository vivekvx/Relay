# PostgreSQL connection setup for the hosted registry (PRD.md §7).
# DATABASE_URL env var, e.g. postgresql+psycopg://user:pass@host/dbname.
# Sync engine/session — no async driver, matches the sync FastAPI
# route style used throughout this component (ponytail: no need for
# asyncpg/async session machinery at this scale).

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://localhost/relay_registry"
)
# Render's provisioned Postgres connection strings use the bare
# "postgresql://" scheme, not SQLAlchemy's "postgresql+psycopg://" —
# normalize so the same DATABASE_URL Render sets works with no manual
# edit.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_session():
    """FastAPI dependency — yields a session, closes it after the request."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
