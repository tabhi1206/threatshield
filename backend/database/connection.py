from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from config.settings import settings

# In SQLite, by default, only one thread can communicate with the database.
# However, FastAPI handles requests asynchronously and runs them on multiple threads.
# Setting check_same_thread=False allows SQLite to accept calls from multiple threads.
# From a security standpoint, we rely on SQLAlchemy's session management to isolate transactions.
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# Create engine instance
# The engine represents the database dialect and connection pool.
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args=connect_args,
    pool_pre_ping=True  # Cybersecurity/Resilience: verify connections prior to usage to prevent stale connection errors
)

# Create SessionLocal class
# Each instance of the SessionLocal class will be a database session.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative database models
# All DB models will inherit from this class to hook into SQLAlchemy's ORM
Base = declarative_base()

def get_db():
    """
    Dependency generator for database sessions.
    Ensures that every API request gets a clean session and that it's closed
    after the request is processed, preventing memory leaks and database connection exhaustion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
