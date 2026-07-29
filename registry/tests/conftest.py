# Spins up an ephemeral, real local Postgres cluster for the test
# session (initdb + pg_ctl on a free port, in a temp data dir) — this
# component's append-only trigger and structural constraints are
# genuinely Postgres-specific (roles/triggers), so a real Postgres
# instance is used rather than a substitute.

import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from registry.db.migrate import apply_schema


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def database_url():
    data_dir = Path(tempfile.mkdtemp(prefix="relay-registry-pg-"))
    port = _free_port()

    subprocess.run(
        ["initdb", "-D", str(data_dir), "-U", "postgres", "-A", "trust", "--no-sync"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "pg_ctl",
            "-D",
            str(data_dir),
            "-o",
            f"-p {port} -k {data_dir} -c listen_addresses=''",
            "-l",
            str(data_dir / "log.txt"),
            "start",
        ],
        check=True,
        capture_output=True,
    )

    url = f"postgresql+psycopg://postgres@/relay_test?host={data_dir}&port={port}"
    admin_url = f"postgresql+psycopg://postgres@/postgres?host={data_dir}&port={port}"

    # Wait for the socket to accept connections, then create the DB.
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
def session(engine):
    Session = sessionmaker(bind=engine, future=True)
    sess = Session()
    yield sess
    sess.rollback()
    sess.close()
    # Clean slate between tests. TRUNCATE fires ON TRUNCATE triggers,
    # not the audit_log's BEFORE UPDATE/DELETE trigger, so this is not
    # blocked by the append-only guarantee.
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE identities, grants, approval_requests, pending_relay_queue, "
                "nonce_log, rate_limit_events, rate_limit_config, approval_expiry_config, "
                "audit_log RESTART IDENTITY CASCADE"
            )
        )
