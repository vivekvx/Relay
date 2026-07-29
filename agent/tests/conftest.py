# Real registry, real ephemeral Postgres, real HTTP layer (ASGI
# transport — no separate process, but the actual FastAPI app +
# SQLAlchemy + Postgres, not a mock). Mirrors
# registry/tests/conftest.py's fixture exactly; duplicated rather than
# imported because agent/ and registry/ are separate deployable
# components (CLAUDE.md §3) that must not depend on each other's
# source at runtime — this is a test-only dependency exception, the
# actual wiring code (agent/wiring/*) never imports anything from
# registry/.

import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from registry.app import app  # noqa: E402
from registry.db import get_session  # noqa: E402
from registry.db.migrate import apply_schema  # noqa: E402

from wiring.registry_client import RegistryClient  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def database_url():
    data_dir = Path(tempfile.mkdtemp(prefix="relay-agent-pg-"))
    port = _free_port()

    subprocess.run(
        ["initdb", "-D", str(data_dir), "-U", "postgres", "-A", "trust", "--no-sync"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["pg_ctl", "-D", str(data_dir), "-o", f"-p {port} -k {data_dir} -c listen_addresses=''",
         "-l", str(data_dir / "log.txt"), "start"],
        check=True, capture_output=True,
    )

    url = f"postgresql+psycopg://postgres@/relay_test?host={data_dir}&port={port}"
    admin_url = f"postgresql+psycopg://postgres@/postgres?host={data_dir}&port={port}"

    admin_engine = create_engine(admin_url, future=True, isolation_level="AUTOCOMMIT")
    for _ in range(50):
        try:
            with admin_engine.connect() as conn:
                conn.execute(text("CREATE DATABASE relay_test"))
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("test Postgres cluster never became ready")
    admin_engine.dispose()

    yield url

    subprocess.run(["pg_ctl", "-D", str(data_dir), "-m", "immediate", "stop"], capture_output=True)
    shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def engine(database_url):
    eng = create_engine(database_url, future=True)
    apply_schema(eng)
    return eng


@pytest.fixture()
def db_session(engine):
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    sess = Session()
    yield sess
    sess.rollback()
    sess.close()
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE identities, grants, approval_requests, pending_relay_queue, "
            "nonce_log, rate_limit_events, rate_limit_config, approval_expiry_config, "
            "audit_log RESTART IDENTITY CASCADE"
        ))


@pytest.fixture(scope="session")
def live_registry_port():
    """The real FastAPI app served over a real TCP socket (uvicorn, in
    a background thread) for the whole test session — genuine HTTP, not
    a mock or an in-process ASGI shortcut."""
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("test registry server never started")
    yield port
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def registry_client(db_session, live_registry_port):
    """A RegistryClient talking to the REAL, running FastAPI app with
    the request-scoped test Postgres session wired in via dependency
    override."""
    app.dependency_overrides[get_session] = lambda: db_session
    client = RegistryClient.create(f"http://127.0.0.1:{live_registry_port}")
    yield client
    app.dependency_overrides.clear()
