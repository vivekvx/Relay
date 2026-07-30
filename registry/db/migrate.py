# Applies schema.sql to DATABASE_URL. No Alembic — a single idempotent
# SQL file is enough at this stage (ponytail: avoid migration-framework
# overhead for a schema this size; revisit if/when it needs versioned
# incremental migrations).
#
# Migration tripwire (registry/ARCHITECTURE.md judgment call #7): the
# CREATE TABLE IF NOT EXISTS statements below silently no-op against an
# existing schema instead of actually migrating it. That's fine against
# a fresh database, but dangerous against a populated one that predates
# a column addition (e.g. identities.x25519_public_key_hex,
# pending_relay_queue.content_ciphertext) — the table would keep
# existing without the new column, and every insert expecting that
# column would fail confusingly at write time instead of at migration
# time. `check_migration_safety` below detects exactly that case and
# refuses to proceed. It is NOT a real migration system — no versioned
# migration files, no rollback, no ALTER TABLE. It only draws a hard
# line between "safe to no-op" and "needs an actual migration you don't
# have yet," per registry/ARCHITECTURE.md's still-unresolved gap.

from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

SCHEMA_PATH = Path(__file__).parent / "schema.sql"

# The concrete case this tripwire exists for (registry/ARCHITECTURE.md
# judgment call #7): columns added in a later task that an
# already-populated, pre-existing table might be missing. Extendable if
# a future column addition needs the same protection, but this fix
# deliberately keeps the check to the columns that motivated it rather
# than trying to diff the entire schema.
REQUIRED_COLUMNS_IF_POPULATED = {
    "identities": {"x25519_public_key_hex", "relay_number"},
    "pending_relay_queue": {"content_ciphertext"},
}


class MigrationSafetyError(RuntimeError):
    pass


def check_migration_safety(engine: Engine) -> None:
    """Refuses to proceed if any table already has rows AND is missing a
    column this fix knows about. Raises MigrationSafetyError naming the
    table(s) and missing column(s). A fresh/empty database (no tables,
    or tables with zero rows) always passes — this only guards the
    populated-but-stale case."""
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    problems: list[str] = []
    with engine.connect() as conn:
        for table, required_columns in REQUIRED_COLUMNS_IF_POPULATED.items():
            if table not in existing_tables:
                continue  # fresh database — CREATE TABLE will make it correctly

            existing_columns = {col["name"] for col in inspector.get_columns(table)}
            missing_columns = required_columns - existing_columns
            if not missing_columns:
                continue  # already has the columns — nothing dangerous here

            row_count = conn.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
            if row_count > 0:
                problems.append(
                    f"table {table!r} has {row_count} row(s) but is missing "
                    f"column(s) {sorted(missing_columns)!r}"
                )

    if problems:
        raise MigrationSafetyError(
            "refusing to apply schema.sql: CREATE TABLE IF NOT EXISTS would "
            "silently no-op against a populated, out-of-date schema instead "
            "of migrating it (see registry/ARCHITECTURE.md judgment call #7, "
            '"No ALTER TABLE migration path"). Problem(s) found: '
            + "; ".join(problems)
            + ". A real migration (ALTER TABLE ADD COLUMN, or a proper "
            "migration tool) is required before this schema can be applied "
            "to this database."
        )


def apply_schema(engine: Engine) -> None:
    check_migration_safety(engine)
    sql = SCHEMA_PATH.read_text()
    with engine.begin() as conn:
        conn.execute(text(sql))


if __name__ == "__main__":
    from . import engine as default_engine

    apply_schema(default_engine)
    print("schema applied")
