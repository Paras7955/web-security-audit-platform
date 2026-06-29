from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def check_database_ready() -> bool:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        required_tables = {
            "platform_users",
            "auth_identities",
            "workspaces",
            "targets",
            "scans",
            "findings",
            "evidence_artifacts",
            "report_artifacts",
        }
        existing_tables = set(inspect(connection).get_table_names())
        missing_tables = required_tables - existing_tables
        if missing_tables:
            raise RuntimeError(f"Database schema is not ready; missing tables: {sorted(missing_tables)}")
    return True
