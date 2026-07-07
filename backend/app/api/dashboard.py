from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import (
    DashboardOverviewRead,
    DashboardScanSummaryRead,
    FindingChangeRead,
    RiskScoreRead,
    ScanComparisonRead,
    TargetDashboardRead,
)
from app.models import Finding, RiskScore, Scan, Target
from app.risk import COMPLETED_SCAN_STATUSES, SCORING_MODEL_VERSION, dedupe_findings, dedupe_findings_by_target, persist_scan_risk_score
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/overview", response_model=DashboardOverviewRead)
def dashboard_overview(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> DashboardOverviewRead:
    targets = list(db.scalars(select(Target).where(Target.workspace_id == principal.workspace_id)).all())
    scans = list(db.scalars(select(Scan).where(Scan.workspace_id == principal.workspace_id).order_by(Scan.created_at.desc())).all())
    completed_scans = [scan for scan in scans if scan.status in COMPLETED_SCAN_STATUSES]
    findings = list(db.scalars(select(Finding).where(Finding.workspace_id == principal.workspace_id)).all())
    target_id_by_scan_id = {scan.id: scan.target_id for scan in scans}
    latest_score = persist_scan_risk_score(db, completed_scans[0], findings_for_scan(findings, completed_scans[0].id)) if completed_scans else None

    return DashboardOverviewRead(
        targets_count=len(targets),
        scans_count=len(scans),
        completed_scans_count=len(completed_scans),
        findings_count=len(findings),
        severity_counts=workspace_severity_counts(findings, target_id_by_scan_id),
        latest_risk_score=latest_score,
        recent_scans=scan_summaries(db, scans[:8], targets_by_id(targets)),
    )


@router.get("/targets/{target_id}/dashboard", response_model=TargetDashboardRead)
def target_dashboard(
    target_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> TargetDashboardRead:
    target = get_target_or_404(db, target_id, principal.workspace_id)
    scans = list(
        db.scalars(
            select(Scan)
            .where(Scan.workspace_id == principal.workspace_id, Scan.target_id == target.id)
            .order_by(Scan.created_at.desc())
        ).all()
    )
    completed_scans = [scan for scan in scans if scan.status in COMPLETED_SCAN_STATUSES]
    findings = list(
        db.scalars(
            select(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Finding.workspace_id == principal.workspace_id, Scan.target_id == target.id)
        ).all()
    )
    latest_score = persist_scan_risk_score(db, completed_scans[0], findings_for_scan(findings, completed_scans[0].id)) if completed_scans else None

    return TargetDashboardRead(
        target_id=target.id,
        target_name=target.name,
        base_url=target.base_url,
        scan_count=len(scans),
        completed_scan_count=len(completed_scans),
        findings_count=len(findings),
        severity_counts=severity_counts(findings),
        latest_risk_score=latest_score,
        recent_scans=scan_summaries(db, scans[:8], {target.id: target}),
    )


@router.get("/scans/{scan_id}/risk-score", response_model=RiskScoreRead)
def scan_risk_score(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> RiskScore:
    scan = get_completed_scan_or_404(db, scan_id, principal.workspace_id)
    findings = list(db.scalars(select(Finding).where(Finding.workspace_id == principal.workspace_id, Finding.scan_id == scan.id)).all())
    return persist_scan_risk_score(db, scan, findings)


@router.get("/scans/{scan_id}/comparison", response_model=ScanComparisonRead)
def compare_scan(
    scan_id: str,
    baseline_scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanComparisonRead:
    comparison_scan = get_completed_scan_or_404(db, scan_id, principal.workspace_id)
    baseline_scan = get_completed_scan_or_404(db, baseline_scan_id, principal.workspace_id)
    return build_comparison(db, baseline_scan, comparison_scan)


@router.get("/targets/{target_id}/latest-comparison", response_model=ScanComparisonRead)
def latest_target_comparison(
    target_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanComparisonRead:
    get_target_or_404(db, target_id, principal.workspace_id)
    completed_scans = list(
        db.scalars(
            select(Scan)
            .where(Scan.workspace_id == principal.workspace_id, Scan.target_id == target_id, Scan.status.in_(COMPLETED_SCAN_STATUSES))
            .order_by(Scan.created_at.desc())
            .limit(2)
        ).all()
    )
    if len(completed_scans) < 2:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="At least two completed scans are required for comparison.")
    return build_comparison(db, completed_scans[1], completed_scans[0])


def build_comparison(db: Session, baseline_scan: Scan, comparison_scan: Scan) -> ScanComparisonRead:
    if baseline_scan.workspace_id != comparison_scan.workspace_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    if baseline_scan.target_id != comparison_scan.target_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scans must belong to the same target.")

    baseline_findings = list(
        db.scalars(select(Finding).where(Finding.workspace_id == baseline_scan.workspace_id, Finding.scan_id == baseline_scan.id)).all()
    )
    comparison_findings = list(
        db.scalars(select(Finding).where(Finding.workspace_id == comparison_scan.workspace_id, Finding.scan_id == comparison_scan.id)).all()
    )
    baseline_score = persist_scan_risk_score(db, baseline_scan, baseline_findings)
    comparison_score = persist_scan_risk_score(db, comparison_scan, comparison_findings)
    baseline_by_key = finding_map(baseline_findings)
    comparison_by_key = finding_map(comparison_findings)

    new_findings: list[FindingChangeRead] = []
    resolved_findings: list[FindingChangeRead] = []
    unchanged_findings: list[FindingChangeRead] = []
    severity_changed_findings: list[FindingChangeRead] = []

    for key in sorted(comparison_by_key):
        current = comparison_by_key[key]
        previous = baseline_by_key.get(key)
        if previous is None:
            new_findings.append(change_for(current, previous_severity=None, current_severity=current.severity))
        elif previous.severity != current.severity:
            severity_changed_findings.append(change_for(current, previous_severity=previous.severity, current_severity=current.severity))
        else:
            unchanged_findings.append(change_for(current, previous_severity=previous.severity, current_severity=current.severity))

    for key in sorted(baseline_by_key):
        if key not in comparison_by_key:
            previous = baseline_by_key[key]
            resolved_findings.append(change_for(previous, previous_severity=previous.severity, current_severity=None))

    return ScanComparisonRead(
        target_id=comparison_scan.target_id,
        baseline_scan_id=baseline_scan.id,
        comparison_scan_id=comparison_scan.id,
        scoring_model_version=SCORING_MODEL_VERSION,
        baseline_score=baseline_score,
        comparison_score=comparison_score,
        score_delta=comparison_score.score - baseline_score.score,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_findings=unchanged_findings,
        severity_changed_findings=severity_changed_findings,
    )


def get_target_or_404(db: Session, target_id: str, workspace_id: str) -> Target:
    target = db.scalar(select(Target).where(Target.id == target_id, Target.workspace_id == workspace_id))
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    return target


def get_completed_scan_or_404(db: Session, scan_id: str, workspace_id: str) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    if scan.status not in COMPLETED_SCAN_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Risk scores require a completed scan.")
    return scan


def scan_summaries(db: Session, scans: list[Scan], target_lookup: dict[str, Target]) -> list[DashboardScanSummaryRead]:
    summaries: list[DashboardScanSummaryRead] = []
    for scan in scans:
        target = target_lookup.get(scan.target_id)
        if target is None:
            continue
        risk_score: RiskScore | None = None
        if scan.status in COMPLETED_SCAN_STATUSES:
            findings = list(db.scalars(select(Finding).where(Finding.workspace_id == scan.workspace_id, Finding.scan_id == scan.id)).all())
            risk_score = persist_scan_risk_score(db, scan, findings)
        summaries.append(
            DashboardScanSummaryRead(
                id=scan.id,
                target_id=scan.target_id,
                target_name=target.name,
                scan_profile_id=scan.scan_profile_id,
                mode=scan.mode,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                risk_score=risk_score,
            )
        )
    return summaries


def targets_by_id(targets: list[Target]) -> dict[str, Target]:
    return {target.id: target for target in targets}


def findings_for_scan(findings: list[Finding], scan_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.scan_id == scan_id]


def finding_map(findings: list[Finding]) -> dict[str, Finding]:
    return {finding.dedupe_key: finding for finding in dedupe_findings(findings)}


def workspace_severity_counts(findings: list[Finding], target_id_by_scan_id: dict[str, str]) -> dict[str, int]:
    target_findings = [(target_id_by_scan_id[finding.scan_id], finding) for finding in findings if finding.scan_id in target_id_by_scan_id]
    counts = Counter(finding.severity for _, finding in dedupe_findings_by_target(target_findings))
    return {severity: counts.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in dedupe_findings(findings))
    return {severity: counts.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}


def change_for(finding: Finding, *, previous_severity: str | None, current_severity: str | None) -> FindingChangeRead:
    return FindingChangeRead(
        dedupe_key=finding.dedupe_key,
        title=finding.title,
        source_tool=finding.source_tool,
        location=finding.affected_url or finding.affected_file,
        previous_severity=previous_severity,
        current_severity=current_severity,
    )
