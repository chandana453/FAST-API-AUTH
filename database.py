# database.py
import os

from sqlalchemy import create_engine, QueuePool
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from urllib.parse import quote_plus

# Replace with your actual credentials
user = os.getenv("user", "postgres")
password = os.getenv("password", "Madhurima@25")
dbname = os.getenv("database", "Modernization")
host = os.getenv("host", "localhost")
port = os.getenv("port", "5432")

# Encode the password to be URL-safe
encoded_password = quote_plus(password)

# Construct the database URL
SQLALCHEMY_DATABASE_URL = f"postgresql://{user}:{encoded_password}@{host}:{port}/{dbname}"
print(SQLALCHEMY_DATABASE_URL)

# Create the engine and sessionmaker
engine = create_engine(SQLALCHEMY_DATABASE_URL,
                       pool_size=5,  # Maximum connections in the pool
                       max_overflow=10,  # Additional connections allowed above `pool_size`
                       pool_timeout=30,  # Maximum time to wait for a connection (in seconds)
                       pool_recycle=1800,  # Recycle connections after 30 minutes (1800 seconds)
                       poolclass=QueuePool  # Default connection pool class; QueuePool is usually sufficient
                       )
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
