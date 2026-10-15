import os
from collections.abc import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Load environment variables from the .env file
load_dotenv()

# Get the database URL from .env
_database_url = os.getenv("DATABASE_URL")

# Check whether DATABASE_URL is configured
if not _database_url:
    raise ValueError(
        "DATABASE_URL is missing. Please check your .env file."
    )

#: Non-empty once the check above passes; annotated so callers (and type
#: checkers) can rely on it being a plain string.
DATABASE_URL: str = _database_url

# Create the SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

# Create the database session factory
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


# Dependency for FastAPI database sessions
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()