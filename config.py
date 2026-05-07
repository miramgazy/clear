import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

CENTRAL_AUTH_URL = os.getenv("CENTRAL_AUTH_URL", "https://clearbat.iiko.tech")

# PostgreSQL Connection Details
PG_USER = os.getenv("POSTGRES_USER", "postgres")
PG_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
PG_DB = os.getenv("POSTGRES_DB", "clear_node")
PG_HOST = os.getenv("POSTGRES_HOST", "localhost")
PG_PORT = os.getenv("POSTGRES_PORT", "5432")

DATABASE_URL = f"postgresql+asyncpg://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DB}"

# Legacy path for reference (not used for Postgres)
DB_PATH = "data/database.db"