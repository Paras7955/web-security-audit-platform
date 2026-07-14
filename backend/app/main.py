from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.ai import router as ai_router
from app.api.auth_profiles import router as auth_profiles_router
from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.middleware import PublicSafetyMiddleware
from app.api.ops import router as ops_router
from app.api.problems import http_exception_handler, unhandled_exception_handler, validation_exception_handler
from app.api.reports import router as reports_router
from app.api.scans import router as scans_router
from app.api.targets import router as targets_router
from app.auth_profiles import validate_auth_profile_secret_settings
from app.core.config import settings
from app.core.contracts import CONTRACTS
from app.core.logging import configure_logging
from app.core.validation import validate_runtime_settings
from app.db.session import check_database_ready
from app.security.auth import validate_auth_settings

configure_logging()

@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_auth_settings(settings)
    validate_auth_profile_secret_settings(settings)
    validate_runtime_settings(settings)
    check_database_ready()
    yield


app = FastAPI(
    title="ScopeHarbor — Local AppSec Audit Platform",
    version=__version__,
    description="Local-first defensive web application security audit platform.",
    lifespan=lifespan,
)

app.add_middleware(PublicSafetyMiddleware, max_body_bytes=settings.max_request_body_bytes)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

for router in (
    targets_router,
    auth_profiles_router,
    scans_router,
    dashboard_router,
    findings_router,
    reports_router,
    ai_router,
    ops_router,
):
    app.include_router(router, prefix="/api/v1")

app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # pyright: ignore[reportArgumentType]
app.add_exception_handler(RequestValidationError, validation_exception_handler)  # pyright: ignore[reportArgumentType]
app.add_exception_handler(Exception, unhandled_exception_handler)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, str]:
    validate_auth_settings(settings)
    validate_auth_profile_secret_settings(settings)
    validate_runtime_settings(settings)
    check_database_ready()
    return {"status": "ready"}


@app.get("/api/v1/contracts", tags=["contracts"])
def contracts() -> dict[str, object]:
    profiles = CONTRACTS.get("scan_profiles")
    acknowledgement_codes = CONTRACTS.get("acknowledgement_codes")
    statuses = CONTRACTS.get("scan_statuses")
    limits = CONTRACTS.get("default_limits")
    return {
        "product": CONTRACTS.get("product", {}),
        "scan_profiles": [
            {
                "id": profile.get("id"),
                "label": profile.get("label"),
                "description": profile.get("description"),
                "required_acknowledgements": profile.get("required_acknowledgements", []),
                "requires_repository": bool(profile.get("requires_repo_path")),
                "local_demo_only": bool(profile.get("local_demo_only")),
                "reports_supported": bool(profile.get("reports_enabled")),
                "ai_explanations_supported": bool(profile.get("ai_enabled")),
            }
            for profile in profiles
            if isinstance(profile, dict)
        ]
        if isinstance(profiles, list)
        else [],
        "acknowledgement_codes": acknowledgement_codes if isinstance(acknowledgement_codes, dict) else {},
        "scan_statuses": statuses if isinstance(statuses, list) else [],
        "pagination": {
            "default_limit": limits.get("page_default_limit", 50),
            "maximum_limit": limits.get("page_max_limit", 200),
        }
        if isinstance(limits, dict)
        else {"default_limit": 50, "maximum_limit": 200},
    }
