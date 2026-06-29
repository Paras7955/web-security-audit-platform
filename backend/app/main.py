from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.ai import router as ai_router
from app.api.findings import router as findings_router
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.api.targets import router as targets_router
from app.core.config import settings
from app.core.contracts import CONTRACTS
from app.db.session import check_database_ready
from app.security.auth import validate_auth_settings

app = FastAPI(
    title="Defensive Web App Security Audit Platform",
    version="0.1.0",
    description="Local-first defensive web application security audit platform.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)
app.include_router(ai_router)


@app.on_event("startup")
def validate_startup_configuration() -> None:
    validate_auth_settings(settings)


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
