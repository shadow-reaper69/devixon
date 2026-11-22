"""
Database session and engine initialization using SQLAlchemy 2.0.
Includes automatic schema migration for SQLite databases.
"""

from pathlib import Path
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from devixon.core.config import load_config, DEFAULT_DATA_DIR

Base = declarative_base()
_engine = None
_SessionFactory = None


def get_engine(db_path: str = None):
    global _engine
    if _engine is None or db_path is not None:
        if db_path is None:
            config = load_config()
            db_path = config.database_path

        p = Path(db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite:///{p.resolve()}"

        _engine = create_engine(db_url, echo=False)

        # Enforce foreign keys in SQLite
        @event.listens_for(_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return _engine


def get_session(db_path: str = None) -> Session:
    global _SessionFactory
    engine = get_engine(db_path)
    if _SessionFactory is None or db_path is not None:
        _SessionFactory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return _SessionFactory()


def run_migrations(engine):
    """
    Ensures existing SQLite tables are migrated with any newly added columns.
    Safe and idempotent.
    """
    with engine.connect() as conn:
        # Check endpoints table columns
        try:
            res = conn.execute(text("PRAGMA table_info(endpoints)")).fetchall()
            existing_cols = {row[1] for row in res}
            if existing_cols and "assessment_id" not in existing_cols:
                conn.execute(text("ALTER TABLE endpoints ADD COLUMN assessment_id VARCHAR(36) REFERENCES assessments(id) ON DELETE CASCADE"))
            if existing_cols and "is_historical" not in existing_cols:
                conn.execute(text("ALTER TABLE endpoints ADD COLUMN is_historical BOOLEAN DEFAULT 0"))
            conn.commit()
        except Exception:
            pass


def init_db(db_path: str = None):
    """Creates all tables and runs schema migrations."""
    engine = get_engine(db_path)
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
