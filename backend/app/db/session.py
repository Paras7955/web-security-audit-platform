from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

EXPECTED_MIGRATION_HEAD = "0011_target_archiving"
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def check_database_ready() -> bool:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        required_tables = {
            "platform_users",
            "auth_identities",
            "workspaces",
            "auth_profiles",
            "targets",
            "scans",
            "findings",
            "risk_scores",
            "finding_states",
            "suppression_rules",
            "finding_occurrence_states",
            "tags",
            "tag_assignments",
            "evidence_artifacts",
            "report_artifacts",
            "ai_request_logs",
            "ai_explanation_cache",
            "api_rate_limit_logs",
            "audit_logs",
            "worker_heartbeats",
            "scanner_tool_runs",
        }
        existing_tables = set(inspect(connection).get_table_names())
        missing_tables = required_tables - existing_tables
        if missing_tables:
            raise RuntimeError(f"Database schema is not ready; missing tables: {sorted(missing_tables)}")
        if "alembic_version" not in existing_tables:
            raise RuntimeError("Database schema is not managed by Alembic.")
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        if revision != EXPECTED_MIGRATION_HEAD:
            raise RuntimeError("Database migration is not at the required ScopeHarbor schema head.")
    return True
