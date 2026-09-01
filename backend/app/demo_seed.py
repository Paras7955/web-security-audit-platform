from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.contracts import ScanStatus, ScanStep
from app.db.session import SessionLocal
from app.finding_management import sync_occurrence_state
from app.models import (
    AuthIdentity,
    Finding,
    FindingState,
    PlatformUser,
    ReportArtifact,
    RepositoryAsset,
    RiskScore,
    Scan,
    SuppressionRule,
    Tag,
    TagAssignment,
    Target,
    Workspace,
)
from app.reports.service import (
    build_report_data,
    render_html_report,
    render_markdown_report,
    safe_report_dir,
    write_report_file,
)
from app.risk import calculate_scan_risk_score
from app.security.allowlist import load_allowlist

DEMO_USER_ID = "dev-user"
DEMO_WORKSPACE_ID = "dev-workspace"
DEMO_PROVIDER = "dev"
DEMO_PROVIDER_SUBJECT = "dev-user"

JUICE_TARGET_ID = "demo-target-juice-shop"
REPO_TARGET_ID = "demo-target-security-project-repo"
REPO_ASSET_ID = "demo-repository-asset-security-project"

BASELINE_SCAN_ID = "demo-scan-juice-baseline"
LATEST_SCAN_ID = "demo-scan-juice-latest"
REPO_SCAN_ID = "demo-scan-repo-latest"

DEMO_STARTED_AT = datetime(2026, 1, 15, 14, 0, tzinfo=UTC)


@dataclass(frozen=True)
class DemoSeedResult:
    workspace_id: str
    user_id: str
    targets: int
    repository_assets: int
    scans: int
    findings: int
    reports: int
    risk_scores: int


@dataclass(frozen=True)
class FindingSeed:
    id: str
    scan_id: str
    title: str
    severity: str
    confidence: str
    dedupe_key: str
    source_tool: str
    scanner_rule_id: str
    affected_url: str | None = None
    affected_file: str | None = None
    evidence: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    reproduction_steps: str | None = None
    remediation: str | None = None
    false_positive_notes: str | None = None


def preflight_seed_collisions(
    db: Session,
    *,
    workspace_id: str,
    user_id: str,
    provider: str,
    provider_subject: str,
) -> None:
    workspace = db.get(Workspace, workspace_id)
    if workspace is not None and workspace.owner_user_id != user_id:
        raise ValueError("Demo seed refused a fixed workspace ID owned by another user.")
    identity = db.scalar(
        select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == provider_subject,
        )
    )
    if identity is not None and identity.user_id != user_id:
        raise ValueError("Demo seed refused a fixed identity bound to another user.")
    fixed_identity = db.get(AuthIdentity, "demo-auth-identity")
    if fixed_identity is not None and (
        fixed_identity.user_id != user_id
        or fixed_identity.provider != provider
        or fixed_identity.provider_subject != provider_subject
    ):
        raise ValueError("Demo seed refused a fixed identity ID bound to another principal.")

    fixed_ids_by_model = {
        Target: (JUICE_TARGET_ID, REPO_TARGET_ID),
        RepositoryAsset: (REPO_ASSET_ID,),
        Scan: (BASELINE_SCAN_ID, LATEST_SCAN_ID, REPO_SCAN_ID),
        Finding: tuple(seed.id for seed in FINDING_SEEDS),
        FindingState: (
            "demo-state-csp",
            "demo-state-xfo",
            "demo-state-cookie",
            "demo-state-repo-api-key",
            "demo-state-server-header",
            "demo-state-repo-dependency",
        ),
        SuppressionRule: ("demo-suppression-repo-api-key",),
        Tag: ("demo-tag-demo-data", "demo-tag-needs-review", "demo-tag-accepted-risk"),
        TagAssignment: ("demo-tag-target-juice", "demo-tag-scan-latest", "demo-tag-scan-repo"),
        RiskScore: ("demo-risk-baseline", "demo-risk-latest", "demo-risk-repo"),
        ReportArtifact: (
            "demo-report-latest-markdown",
            "demo-report-latest-html",
            "demo-report-repo-markdown",
            "demo-report-repo-html",
        ),
    }
    for model, fixed_ids in fixed_ids_by_model.items():
        rows = db.scalars(select(model).where(model.id.in_(fixed_ids))).all()
        if any(row.workspace_id != workspace_id for row in rows):
            raise ValueError("Demo seed refused a fixed record ID owned by another workspace.")


FINDING_SEEDS = (
    FindingSeed(
        id="demo-finding-baseline-csp",
        scan_id=BASELINE_SCAN_ID,
        title="Missing Content Security Policy",
        severity="medium",
        confidence="high",
        dedupe_key="demo:juice-shop:csp",
        source_tool="zap",
        scanner_rule_id="10038",
        affected_url="http://juice-shop:3000/",
        evidence="response header content-security-policy was not present",
        cwe="CWE-693",
        owasp_category="A05:2021",
        reproduction_steps="Open the home page and inspect response security headers.",
        remediation="Add a restrictive Content-Security-Policy header for browser-delivered pages.",
    ),
    FindingSeed(
        id="demo-finding-baseline-xfo",
        scan_id=BASELINE_SCAN_ID,
        title="Missing Anti-Clickjacking Header",
        severity="low",
        confidence="high",
        dedupe_key="demo:juice-shop:x-frame-options",
        source_tool="zap",
        scanner_rule_id="10020",
        affected_url="http://juice-shop:3000/",
        evidence="x-frame-options header was not present",
        cwe="CWE-1021",
        owasp_category="A05:2021",
        reproduction_steps="Open the home page and inspect response security headers.",
        remediation="Add frame-ancestors in CSP or X-Frame-Options for legacy browser coverage.",
    ),
    FindingSeed(
        id="demo-finding-latest-csp",
        scan_id=LATEST_SCAN_ID,
        title="Missing Content Security Policy",
        severity="high",
        confidence="high",
        dedupe_key="demo:juice-shop:csp",
        source_tool="zap",
        scanner_rule_id="10038",
        affected_url="http://juice-shop:3000/",
        evidence="response header content-security-policy was not present",
        cwe="CWE-693",
        owasp_category="A05:2021",
        reproduction_steps="Open the home page and inspect response security headers.",
        remediation="Add and test a restrictive Content-Security-Policy header before release.",
    ),
    FindingSeed(
        id="demo-finding-latest-cookie",
        scan_id=LATEST_SCAN_ID,
        title="Cookie Missing SameSite Attribute",
        severity="medium",
        confidence="high",
        dedupe_key="demo:juice-shop:cookie-samesite",
        source_tool="zap",
        scanner_rule_id="10054",
        affected_url="http://juice-shop:3000/",
        evidence="set-cookie observed without SameSite attribute; cookie value redacted",
        cwe="CWE-614",
        owasp_category="A05:2021",
        reproduction_steps="Start a local session and inspect Set-Cookie response headers.",
        remediation="Set SameSite=Lax or SameSite=Strict on session cookies where compatible.",
    ),
    FindingSeed(
        id="demo-finding-latest-version",
        scan_id=LATEST_SCAN_ID,
        title="Informational Server Header",
        severity="info",
        confidence="medium",
        dedupe_key="demo:juice-shop:server-header",
        source_tool="custom-passive",
        scanner_rule_id="header-server",
        affected_url="http://juice-shop:3000/",
        evidence="server header present with non-sensitive product information",
        cwe="CWE-200",
        owasp_category="A05:2021",
        reproduction_steps="Inspect response headers for the local demo target.",
        remediation="Remove or minimize server version headers if not needed for operations.",
    ),
    FindingSeed(
        id="demo-finding-repo-api-key",
        scan_id=REPO_SCAN_ID,
        title="Hardcoded API Key Pattern",
        severity="high",
        confidence="confirmed",
        dedupe_key="demo:repo:hardcoded-api-key",
        source_tool="gitleaks",
        scanner_rule_id="generic-api-key",
        affected_file="example.env",
        evidence="api_key=[REDACTED]",
        cwe="CWE-798",
        owasp_category="A02:2021",
        reproduction_steps="Review committed configuration examples for credential-like values.",
        remediation="Move real secrets to local environment variables or a secret manager.",
        false_positive_notes="Seeded demo finding; no real secret is present.",
    ),
    FindingSeed(
        id="demo-finding-repo-dependency",
        scan_id=REPO_SCAN_ID,
        title="Outdated Demo Dependency",
        severity="medium",
        confidence="medium",
        dedupe_key="demo:repo:outdated-demo-dependency",
        source_tool="osv-scanner",
        scanner_rule_id="dependency-version-demo",
        affected_file="package.json",
        evidence="demo dependency version is intentionally illustrative",
        cwe="CWE-1104",
        owasp_category="A06:2021",
        reproduction_steps="Inspect dependency metadata in the configured local repository path.",
        remediation="Review dependency update policy and keep production dependencies current.",
    ),
)


def seed_demo_data(
    db: Session,
    *,
    artifact_root: str | Path,
    repo_scan_root: str | Path,
    user_id: str = DEMO_USER_ID,
    workspace_id: str = DEMO_WORKSPACE_ID,
    provider: str = DEMO_PROVIDER,
    provider_subject: str = DEMO_PROVIDER_SUBJECT,
) -> DemoSeedResult:
    artifact_root_path = Path(artifact_root)
    repo_scan_root_path = Path(repo_scan_root)
    preflight_seed_collisions(
        db,
        workspace_id=workspace_id,
        user_id=user_id,
        provider=provider,
        provider_subject=provider_subject,
    )
    repo_path = ensure_demo_repo_path(repo_scan_root_path)

    upsert_identity(
        db,
        user_id=user_id,
        workspace_id=workspace_id,
        provider=provider,
        provider_subject=provider_subject,
    )
    upsert_targets(db, workspace_id=workspace_id, user_id=user_id, repo_path=repo_path)
    upsert_repository_asset(db, workspace_id=workspace_id, user_id=user_id, repo_path=repo_path)
    db.flush()
    upsert_scans(db, workspace_id=workspace_id, user_id=user_id)
    db.flush()
    upsert_findings(db, workspace_id=workspace_id)
    upsert_management_examples(db, workspace_id=workspace_id, user_id=user_id)
    upsert_risk_scores(db)
    upsert_reports(db, artifact_root=artifact_root_path, workspace_id=workspace_id, user_id=user_id)
    db.commit()

    return DemoSeedResult(
        workspace_id=workspace_id,
        user_id=user_id,
        targets=count_seeded(db, Target, (JUICE_TARGET_ID, REPO_TARGET_ID)),
        repository_assets=count_seeded(db, RepositoryAsset, (REPO_ASSET_ID,)),
        scans=count_seeded(db, Scan, (BASELINE_SCAN_ID, LATEST_SCAN_ID, REPO_SCAN_ID)),
        findings=count_seeded(db, Finding, tuple(seed.id for seed in FINDING_SEEDS)),
        reports=count_seeded(
            db,
            ReportArtifact,
            (
                "demo-report-latest-markdown",
                "demo-report-latest-html",
                "demo-report-repo-markdown",
                "demo-report-repo-html",
            ),
        ),
        risk_scores=count_seeded(
            db,
            RiskScore,
            (
                "demo-risk-baseline",
                "demo-risk-latest",
                "demo-risk-repo",
            ),
        ),
    )


def ensure_demo_repo_path(repo_scan_root: Path) -> Path:
    root = repo_scan_root.resolve()
    repo_path = (root / "security-project").resolve()
    if root not in repo_path.parents and repo_path != root:
        raise ValueError("Demo repository path must stay under REPO_SCAN_ROOT.")
    repo_path.mkdir(parents=True, exist_ok=True)
    return repo_path


def upsert_identity(
    db: Session,
    *,
    user_id: str,
    workspace_id: str,
    provider: str,
    provider_subject: str,
) -> None:
    user = db.get(PlatformUser, user_id)
    if user is None:
        user = PlatformUser(id=user_id, display_name="Demo User")
    else:
        user.display_name = user.display_name or "Demo User"
    db.add(user)
    db.flush()

    workspace = db.get(Workspace, workspace_id)
    if workspace is None:
        workspace = Workspace(id=workspace_id, owner_user_id=user_id, name="Demo Workspace")
    else:
        workspace.owner_user_id = user_id
        workspace.name = workspace.name or "Demo Workspace"
    db.add(workspace)
    db.flush()

    identity = db.scalar(
        select(AuthIdentity).where(
            AuthIdentity.provider == provider,
            AuthIdentity.provider_subject == provider_subject,
        )
    )
    if identity is None:
        identity = AuthIdentity(
            id="demo-auth-identity",
            user_id=user_id,
            provider=provider,
            provider_subject=provider_subject,
        )
    else:
        identity.user_id = user_id
    db.add(identity)
    db.flush()


def upsert_targets(db: Session, *, workspace_id: str, user_id: str, repo_path: Path) -> None:
    policy = load_allowlist(settings.allowlist_path).get_target("juice-shop")
    if policy is None:
        raise ValueError("Demo seed requires the bundled juice-shop policy.")
    targets = (
        Target(
            id=JUICE_TARGET_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            allowlist_id="juice-shop",
            name="OWASP Juice Shop Demo",
            base_url="http://juice-shop:3000",
            policy_fingerprint=policy.policy_fingerprint,
            policy_scope_base_url=policy.base_url,
            permission_confirmed=True,
            authorization_confirmed_at=DEMO_STARTED_AT,
            repo_path=None,
            auth_profile_id=None,
        ),
        Target(
            id=REPO_TARGET_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            allowlist_id="juice-shop",
            name="Security Project Repository Demo",
            base_url="http://juice-shop:3000",
            policy_fingerprint=policy.policy_fingerprint,
            policy_scope_base_url=policy.base_url,
            permission_confirmed=True,
            authorization_confirmed_at=DEMO_STARTED_AT,
            repo_path=repo_path.name,
            auth_profile_id=None,
        ),
    )
    for target in targets:
        merge_model(db, target)


def upsert_repository_asset(
    db: Session,
    *,
    workspace_id: str,
    user_id: str,
    repo_path: Path,
) -> None:
    merge_model(
        db,
        RepositoryAsset(
            id=REPO_ASSET_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            name="Security Project Repository Demo",
            relative_path=repo_path.name,
            permission_confirmed=True,
            authorization_confirmed_at=DEMO_STARTED_AT,
        ),
    )


def upsert_scans(db: Session, *, workspace_id: str, user_id: str) -> None:
    policy = load_allowlist(settings.allowlist_path).get_target("juice-shop")
    if policy is None:
        raise ValueError("Demo seed requires the bundled juice-shop policy.")
    web_authorization_snapshot = {
        "subject_type": "web_target",
        "subject_id": JUICE_TARGET_ID,
        "target_url": "http://juice-shop:3000",
        "allowlist_id": policy.id,
        "policy_fingerprint": policy.policy_fingerprint,
        "auth_profile_id": None,
    }
    scans = (
        Scan(
            id=BASELINE_SCAN_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            target_id=JUICE_TARGET_ID,
            target_policy_fingerprint=policy.policy_fingerprint,
            acknowledgements_snapshot=["authorized_target"],
            authorization_snapshot=web_authorization_snapshot,
            mode="passive",
            scan_profile_id="passive-web",
            status=ScanStatus.COMPLETED.value,
            current_step=ScanStep.NORMALIZING_FINDINGS.value,
            status_message="Seeded baseline passive-web scan.",
            progress_percent=100,
            started_at=DEMO_STARTED_AT,
            completed_at=DEMO_STARTED_AT + timedelta(minutes=5),
            error_code=None,
            error_detail=None,
            attempt_count=0,
            created_at=DEMO_STARTED_AT,
        ),
        Scan(
            id=LATEST_SCAN_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            target_id=JUICE_TARGET_ID,
            target_policy_fingerprint=policy.policy_fingerprint,
            acknowledgements_snapshot=["authorized_target"],
            authorization_snapshot=web_authorization_snapshot,
            mode="passive",
            scan_profile_id="passive-web",
            status=ScanStatus.COMPLETED_WITH_WARNINGS.value,
            current_step=ScanStep.NORMALIZING_FINDINGS.value,
            status_message="Seeded latest passive-web scan with demo findings.",
            progress_percent=100,
            started_at=DEMO_STARTED_AT + timedelta(days=1),
            completed_at=DEMO_STARTED_AT + timedelta(days=1, minutes=6),
            error_code=None,
            error_detail=None,
            attempt_count=0,
            created_at=DEMO_STARTED_AT + timedelta(days=1),
        ),
        Scan(
            id=REPO_SCAN_ID,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            target_id=None,
            repository_asset_id=REPO_ASSET_ID,
            repo_path_snapshot="security-project",
            acknowledgements_snapshot=["authorized_repository"],
            authorization_snapshot={
                "subject_type": "repository_asset",
                "subject_id": REPO_ASSET_ID,
                "relative_path": "security-project",
            },
            mode="repo",
            scan_profile_id="repository",
            status=ScanStatus.COMPLETED.value,
            current_step=ScanStep.NORMALIZING_FINDINGS.value,
            status_message="Seeded repository scan example using safe normalized findings.",
            progress_percent=100,
            started_at=DEMO_STARTED_AT + timedelta(days=2),
            completed_at=DEMO_STARTED_AT + timedelta(days=2, minutes=4),
            error_code=None,
            error_detail=None,
            attempt_count=0,
            created_at=DEMO_STARTED_AT + timedelta(days=2),
        ),
    )
    for scan in scans:
        merge_model(db, scan)


def upsert_findings(db: Session, *, workspace_id: str) -> None:
    for seed in FINDING_SEEDS:
        finding = Finding(
            id=seed.id,
            workspace_id=workspace_id,
            scan_id=seed.scan_id,
            title=seed.title,
            severity=seed.severity,
            confidence=seed.confidence,
            affected_url=seed.affected_url,
            affected_file=seed.affected_file,
            evidence=seed.evidence,
            source_tool=seed.source_tool,
            scanner_rule_id=seed.scanner_rule_id,
            dedupe_key=seed.dedupe_key,
            owasp_category=seed.owasp_category,
            cwe=seed.cwe,
            reproduction_steps=seed.reproduction_steps,
            remediation=seed.remediation,
            false_positive_notes=seed.false_positive_notes,
            redaction_applied=True,
        )
        merge_model(db, finding)
    db.flush()


def upsert_management_examples(db: Session, *, workspace_id: str, user_id: str) -> None:
    states = (
        FindingState(
            id="demo-state-csp",
            workspace_id=workspace_id,
            target_id=JUICE_TARGET_ID,
            dedupe_key="demo:juice-shop:csp",
            lifecycle_status="in_progress",
            updated_by_user_id=user_id,
        ),
        FindingState(
            id="demo-state-xfo",
            workspace_id=workspace_id,
            target_id=JUICE_TARGET_ID,
            dedupe_key="demo:juice-shop:x-frame-options",
            lifecycle_status="resolved",
            updated_by_user_id=user_id,
        ),
        FindingState(
            id="demo-state-cookie",
            workspace_id=workspace_id,
            target_id=JUICE_TARGET_ID,
            dedupe_key="demo:juice-shop:cookie-samesite",
            lifecycle_status="confirmed",
            updated_by_user_id=user_id,
        ),
        FindingState(
            id="demo-state-repo-api-key",
            workspace_id=workspace_id,
            target_id=None,
            repository_asset_id=REPO_ASSET_ID,
            dedupe_key="demo:repo:hardcoded-api-key",
            lifecycle_status="suppressed",
            updated_by_user_id=user_id,
        ),
        FindingState(
            id="demo-state-server-header",
            workspace_id=workspace_id,
            target_id=JUICE_TARGET_ID,
            dedupe_key="demo:juice-shop:server-header",
            lifecycle_status="open",
            updated_by_user_id=user_id,
        ),
        FindingState(
            id="demo-state-repo-dependency",
            workspace_id=workspace_id,
            target_id=None,
            repository_asset_id=REPO_ASSET_ID,
            dedupe_key="demo:repo:outdated-demo-dependency",
            lifecycle_status="open",
            updated_by_user_id=user_id,
        ),
    )
    for state in states:
        merge_model(db, state)

    suppression = SuppressionRule(
        id="demo-suppression-repo-api-key",
        workspace_id=workspace_id,
        target_id=None,
        repository_asset_id=REPO_ASSET_ID,
        dedupe_key="demo:repo:hardcoded-api-key",
        severity=None,
        source_tool="gitleaks",
        reason="Seeded demo suppression for a known non-production example.",
        created_by_user_id=user_id,
        expires_at=DEMO_STARTED_AT + timedelta(days=365),
    )
    merge_model(db, suppression)
    db.flush()

    tags = (
        Tag(id="demo-tag-demo-data", workspace_id=workspace_id, label="demo-data", created_by_user_id=user_id),
        Tag(id="demo-tag-needs-review", workspace_id=workspace_id, label="needs-review", created_by_user_id=user_id),
        Tag(id="demo-tag-accepted-risk", workspace_id=workspace_id, label="accepted-risk", created_by_user_id=user_id),
    )
    for tag in tags:
        merge_model(db, tag)

    assignments = (
        TagAssignment(
            id="demo-tag-target-juice",
            workspace_id=workspace_id,
            tag_id="demo-tag-demo-data",
            resource_type="target",
            resource_id=JUICE_TARGET_ID,
            created_by_user_id=user_id,
        ),
        TagAssignment(
            id="demo-tag-scan-latest",
            workspace_id=workspace_id,
            tag_id="demo-tag-needs-review",
            resource_type="scan",
            resource_id=LATEST_SCAN_ID,
            created_by_user_id=user_id,
        ),
        TagAssignment(
            id="demo-tag-scan-repo",
            workspace_id=workspace_id,
            tag_id="demo-tag-accepted-risk",
            resource_type="scan",
            resource_id=REPO_SCAN_ID,
            created_by_user_id=user_id,
        ),
    )
    for assignment in assignments:
        merge_model(db, assignment)

    for seed in FINDING_SEEDS:
        finding = db.get(Finding, seed.id)
        scan = db.get(Scan, seed.scan_id)
        if finding is not None and scan is not None:
            occurrence = sync_occurrence_state(db, finding, scan, user_id)
            if seed.id == "demo-finding-repo-api-key":
                occurrence.lifecycle_status = "suppressed"
                occurrence.suppressed = True
                occurrence.suppression_rule_id = "demo-suppression-repo-api-key"
                db.add(occurrence)


def upsert_risk_scores(db: Session) -> None:
    risk_ids = {
        BASELINE_SCAN_ID: "demo-risk-baseline",
        LATEST_SCAN_ID: "demo-risk-latest",
        REPO_SCAN_ID: "demo-risk-repo",
    }
    for scan_id, risk_id in risk_ids.items():
        scan = db.get(Scan, scan_id)
        if scan is None:
            continue
        findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id, Finding.workspace_id == scan.workspace_id)).all())
        calculated = calculate_scan_risk_score(scan, findings)
        risk = RiskScore(
            id=risk_id,
            workspace_id=scan.workspace_id,
            target_id=scan.target_id,
            repository_asset_id=scan.repository_asset_id,
            scan_id=scan.id,
            scoring_model_version=calculated.scoring_model_version,
            score=calculated.score,
            label=calculated.label,
            input_summary=calculated.input_summary,
        )
        merge_model(db, risk)


def upsert_reports(db: Session, *, artifact_root: Path, workspace_id: str, user_id: str) -> None:
    report_data = {
        scan_id: build_report_data(db, scan_id=scan_id, workspace_id=workspace_id)
        for scan_id in (LATEST_SCAN_ID, REPO_SCAN_ID)
    }
    report_specs = (
        (LATEST_SCAN_ID, "demo-report-latest-markdown", "markdown", "report.md"),
        (LATEST_SCAN_ID, "demo-report-latest-html", "html", "report.html"),
        (REPO_SCAN_ID, "demo-report-repo-markdown", "markdown", "report.md"),
        (REPO_SCAN_ID, "demo-report-repo-html", "html", "report.html"),
    )
    for scan_id, report_id, report_type, filename in report_specs:
        scan = db.get(Scan, scan_id)
        if scan is None:
            continue
        report_dir = safe_report_dir(artifact_root, scan_id)
        report_path = report_dir / filename
        data = report_data[scan_id]
        content = render_html_report(data) if report_type == "html" else render_markdown_report(data)
        write_report_file(report_path, content)
        artifact = ReportArtifact(
            id=report_id,
            workspace_id=workspace_id,
            created_by_user_id=user_id,
            scan_id=scan_id,
            report_type=report_type,
            path=str(report_path.resolve()),
            created_at=scan.completed_at,
        )
        merge_model(db, artifact)

def merge_model(db: Session, incoming):
    existing = db.get(type(incoming), incoming.id)
    if existing is None:
        db.add(incoming)
        return incoming
    for column in incoming.__table__.columns:
        if column.name in {"created_at", "updated_at"}:
            continue
        setattr(existing, column.name, getattr(incoming, column.name))
    db.add(existing)
    return existing


def count_seeded(db: Session, model, ids: tuple[str, ...]) -> int:
    return len(db.scalars(select(model).where(model.id.in_(ids))).all())


def main() -> None:
    if not settings.demo_seed_enabled:
        raise SystemExit("DEMO_SEED_ENABLED=true is required to run the demo seed command.")
    if settings.auth_mode.strip().lower() != "dev" or settings.auth_provider.strip().lower() != "dev":
        raise SystemExit("Demo seed is only available with AUTH_MODE=dev and AUTH_PROVIDER=dev.")
    with SessionLocal() as db:
        result = seed_demo_data(
            db,
            artifact_root=settings.artifact_root,
            repo_scan_root=settings.repo_scan_root,
            user_id=settings.dev_auth_user_id,
            workspace_id=settings.dev_auth_workspace_id,
            provider=settings.auth_provider,
            provider_subject=settings.dev_auth_subject,
        )
    print(
        "Seeded demo data: "
        f"workspace={result.workspace_id} targets={result.targets} scans={result.scans} "
        f"findings={result.findings} reports={result.reports} risk_scores={result.risk_scores}"
    )


if __name__ == "__main__":
    main()
