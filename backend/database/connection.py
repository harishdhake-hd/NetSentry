"""
backend/database/connection.py

Database connection and session management.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from backend.config import config

# Create the database URL
database_url = config.get_database_url()

# Create engine with appropriate settings for SQLite
if "sqlite" in database_url:
    # For SQLite, use StaticPool to avoid threading issues
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(database_url, pool_pre_ping=True)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_session() -> Session:
    """Get a new database session."""
    return SessionLocal()


def get_engine():
    """Get the SQLAlchemy engine."""
    return engine


def ensure_database_directory():
    """Ensure the database directory exists."""
    if "sqlite" in database_url:
        # Extract directory path from SQLite URL
        # Format: sqlite:///./data/netsentry.db
        parts = database_url.replace("sqlite:///", "").rsplit("/", 1)
        if len(parts) == 2:
            db_dir = parts[0]
            if db_dir and db_dir != ".":
                os.makedirs(db_dir, exist_ok=True)


def init_db():
    """Initialize the database by creating all tables."""
    from backend.database.models import Base

    ensure_database_directory()
    Base.metadata.create_all(bind=engine)


def test_connection() -> bool:
    """Test database connectivity."""
    try:
        session = get_db_session()
        session.execute("SELECT 1")
        session.close()
        return True
    except Exception as e:
        print(f"[ERROR] Database connection failed: {e}")
        return False
