from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Columns added to a model *after* a table already had rows in someone's live
# garuda.db — Base.metadata.create_all only creates whole missing tables, it never
# alters an existing one. Each entry here is an additive, idempotent ALTER TABLE;
# never remove an entry once shipped, since an older db might still be missing it.
_ADDITIVE_COLUMN_MIGRATIONS = [
    ("assets", "attack_reasons", "TEXT DEFAULT '[]'"),
    ("events", "conn_status", "TEXT"),
]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _apply_additive_migrations():
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, column, ddl_type in _ADDITIVE_COLUMN_MIGRATIONS:
            if table not in existing_tables:
                continue  # brand new table — create_all already gave it every column
            existing_columns = {c["name"] for c in inspector.get_columns(table)}
            if column not in existing_columns:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))


def init_db():
    from . import models  # noqa: F401  (ensure models are registered)
    from .scenarios.topology import seed_topology

    Base.metadata.create_all(bind=engine)
    _apply_additive_migrations()

    db = SessionLocal()
    try:
        seed_topology(db)
    finally:
        db.close()
