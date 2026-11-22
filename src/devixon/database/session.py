"""
Database session and engine initialization using SQLAlchemy 2.0.
"""

from pathlib import Path
from sqlalchemy import create_engine, event
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


def init_db(db_path: str = None):
    """Creates all tables."""
    engine = get_engine(db_path)
    Base.metadata.create_all(bind=engine)
