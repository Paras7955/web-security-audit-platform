from fastapi import FastAPI

from app.core.config import settings
from app.core.contracts import CONTRACTS
from app.db.session import check_database_ready

app = FastAPI(
    title="Defensive Web App Security Audit Platform",
    version="0.1.0",
    description="Local-first defensive web application security audit platform.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, str]:
    check_database_ready()
    return {"status": "ready"}


@app.get("/contracts")
def contracts() -> dict[str, object]:
    return {
        **CONTRACTS,
        "ai_provider": settings.ai_provider,
    }
