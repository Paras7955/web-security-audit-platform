from collections import Counter
from typing import overload

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import (
    DashboardOverviewRead,
    DashboardScanSummaryRead,
    FindingChangeRead,
    RepositoryDashboardRead,
    RiskScoreRead,
    ScanComparisonRead,
    TargetDashboardRead,
)
from app.finding_management import occurrence_state_for_read
from app.models import Finding, RepositoryAsset, RiskScore, Scan, Target
from app.risk import (
    COMPLETED_SCAN_STATUSES,
    SCORING_MODEL_VERSION,
    calculate_posture_risk_score,
    dedupe_findings,
    dedupe_findings_by_subject,
    read_scan_risk_score,
)
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/overview", response_model=DashboardOverviewRead)
def dashboard_overview(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> DashboardOverviewRead:
    targets = list(db.scalars(select(Target).where(Target.workspace_id == principal.workspace_id)).all())
    repository_assets = list(
        db.scalars(
            select(RepositoryAsset).where(RepositoryAsset.workspace_id == principal.workspace_id)
        ).all()
    )
    scans = list(
        db.scalars(
            select(Scan)
            .where(Scan.workspace_id == principal.workspace_id)
            .order_by(Scan.created_at.desc())
        ).all()
    )
    completed_scans = sort_completed_scans(
        [scan for scan in scans if scan.status in COMPLETED_SCAN_STATUSES]
    )
    active_target_ids = {target.id for target in targets if target.archived_at is None}
    active_repository_asset_ids = {
        asset.id for asset in repository_assets if asset.archived_at is None
    }
    active_completed_scans = [
        scan
        for scan in completed_scans
        if (
            scan.target_id in active_target_ids
            or scan.repository_asset_id in active_repository_asset_ids
        )
    ]
    historical_findings = findings_for_scans(db, principal.workspace_id, [scan.id for scan in scans])
    posture_scans = latest_completed_scans_per_subject_profile(active_completed_scans)
    posture_findings = effective_posture_findings(db, posture_scans)
    latest_score = (
        read_scan_risk_score(
            db,
            active_completed_scans[0],
            findings_for_scan(historical_findings, active_completed_scans[0].id),
        )
        if active_completed_scans
        else None
    )

    return DashboardOverviewRead(
        targets_count=sum(target.archived_at is None and target.repo_path is None for target in targets),
        repository_assets_count=sum(asset.archived_at is None for asset in repository_assets),
        scans_count=len(scans),
        completed_scans_count=len(completed_scans),
        findings_count=posture_finding_count(posture_findings, posture_scans),
        severity_counts=posture_severity_counts(posture_findings, posture_scans),
        latest_risk_score=risk_score_to_read(latest_score),
        recent_scans=scan_summaries(
            db,
            scans[:8],
            targets_by_id(targets),
            repository_assets_by_id(repository_assets),
        ),
        current_posture_score=posture_score_to_read(posture_findings, posture_scans),
        historical_findings_count=len(historical_findings),
        historical_severity_counts=historical_severity_counts(historical_findings),
    )


@router.get("/targets/{target_id}/dashboard", response_model=TargetDashboardRead)
def target_dashboard(
    target_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> TargetDashboardRead:
    target = get_target_or_404(db, target_id, principal.workspace_id)
    scans = subject_scans(db, principal.workspace_id, target_id=target.id)
    completed_scans = sort_completed_scans(
        [scan for scan in scans if scan.status in COMPLETED_SCAN_STATUSES]
    )
    historical_findings = findings_for_scans(db, principal.workspace_id, [scan.id for scan in scans])
    posture_scans = latest_completed_scans_per_subject_profile(completed_scans)
    posture_findings = effective_posture_findings(db, posture_scans)
    latest_score = (
        read_scan_risk_score(
            db,
            completed_scans[0],
            findings_for_scan(historical_findings, completed_scans[0].id),
        )
        if completed_scans
        else None
    )

    return TargetDashboardRead(
        target_id=target.id,
        target_name=target.name,
        base_url=target.base_url,
        scan_count=len(scans),
        completed_scan_count=len(completed_scans),
        findings_count=posture_finding_count(posture_findings, posture_scans),
        severity_counts=severity_counts(posture_findings),
        latest_risk_score=risk_score_to_read(latest_score),
        recent_scans=scan_summaries(db, scans[:8], {target.id: target}, {}),
        current_posture_score=posture_score_to_read(posture_findings, posture_scans),
        historical_findings_count=len(historical_findings),
        historical_severity_counts=historical_severity_counts(historical_findings),
    )


@router.get(
    "/repository-assets/{repository_asset_id}/dashboard",
    response_model=RepositoryDashboardRead,
)
def repository_asset_dashboard(
    repository_asset_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> RepositoryDashboardRead:
    asset = get_repository_asset_or_404(db, repository_asset_id, principal.workspace_id)
    scans = subject_scans(db, principal.workspace_id, repository_asset_id=asset.id)
    completed_scans = sort_completed_scans(
        [scan for scan in scans if scan.status in COMPLETED_SCAN_STATUSES]
    )
    historical_findings = findings_for_scans(db, principal.workspace_id, [scan.id for scan in scans])
    posture_scans = latest_completed_scans_per_subject_profile(completed_scans)
    posture_findings = effective_posture_findings(db, posture_scans)
    latest_score = (
        read_scan_risk_score(
            db,
            completed_scans[0],
            findings_for_scan(historical_findings, completed_scans[0].id),
        )
        if completed_scans
        else None
    )

    return RepositoryDashboardRead(
        repository_asset_id=asset.id,
        repository_asset_name=asset.name,
        relative_path=asset.relative_path,
        scan_count=len(scans),
        completed_scan_count=len(completed_scans),
        findings_count=posture_finding_count(posture_findings, posture_scans),
        severity_counts=severity_counts(posture_findings),
        latest_risk_score=risk_score_to_read(latest_score),
        recent_scans=scan_summaries(db, scans[:8], {}, {asset.id: asset}),
        current_posture_score=posture_score_to_read(posture_findings, posture_scans),
        historical_findings_count=len(historical_findings),
        historical_severity_counts=historical_severity_counts(historical_findings),
    )


@router.get("/scans/{scan_id}/risk-score", response_model=RiskScoreRead)
def scan_risk_score(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> RiskScore:
    scan = get_completed_scan_or_404(db, scan_id, principal.workspace_id)
    findings = findings_for_scans(db, principal.workspace_id, [scan.id])
    return read_scan_risk_score(db, scan, findings)


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
    return latest_subject_comparison(db, principal.workspace_id, target_id=target_id)


@router.get(
    "/repository-assets/{repository_asset_id}/latest-comparison",
    response_model=ScanComparisonRead,
)
def latest_repository_comparison(
    repository_asset_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> ScanComparisonRead:
    get_repository_asset_or_404(db, repository_asset_id, principal.workspace_id)
    return latest_subject_comparison(
        db,
        principal.workspace_id,
        repository_asset_id=repository_asset_id,
    )


def latest_subject_comparison(
    db: Session,
    workspace_id: str,
    *,
    target_id: str | None = None,
    repository_asset_id: str | None = None,
) -> ScanComparisonRead:
    statement = select(Scan).where(
        Scan.workspace_id == workspace_id,
        Scan.target_id == target_id,
        Scan.repository_asset_id == repository_asset_id,
        Scan.status.in_(COMPLETED_SCAN_STATUSES),
    )
    latest_scan = db.scalar(
        statement.order_by(
            Scan.completed_at.desc().nullslast(),
            Scan.created_at.desc(),
            Scan.id.desc(),
        ).limit(1)
    )
    if latest_scan is None:
        raise comparison_not_found()
    baseline_scan = db.scalar(
        statement.where(
            Scan.scan_profile_id == latest_scan.scan_profile_id,
            Scan.id != latest_scan.id,
        )
        .order_by(
            Scan.completed_at.desc().nullslast(),
            Scan.created_at.desc(),
            Scan.id.desc(),
        )
        .limit(1)
    )
    if baseline_scan is None:
        raise comparison_not_found()
    return build_comparison(db, baseline_scan, latest_scan)


def build_comparison(db: Session, baseline_scan: Scan, comparison_scan: Scan) -> ScanComparisonRead:
    if baseline_scan.workspace_id != comparison_scan.workspace_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    if (
        baseline_scan.target_id != comparison_scan.target_id
        or baseline_scan.repository_asset_id != comparison_scan.repository_asset_id
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scans must belong to the same subject.",
        )
    if baseline_scan.scan_profile_id != comparison_scan.scan_profile_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scans must use the same audit profile.",
        )

    baseline_findings = findings_for_scans(
        db,
        baseline_scan.workspace_id,
        [baseline_scan.id],
    )
    comparison_findings = findings_for_scans(
        db,
        comparison_scan.workspace_id,
        [comparison_scan.id],
    )
    baseline_score = read_scan_risk_score(db, baseline_scan, baseline_findings)
    comparison_score = read_scan_risk_score(db, comparison_scan, comparison_findings)
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
            new_findings.append(
                change_for(current, previous_severity=None, current_severity=current.severity)
            )
        elif previous.severity != current.severity:
            severity_changed_findings.append(
                change_for(
                    current,
                    previous_severity=previous.severity,
                    current_severity=current.severity,
                )
            )
        else:
            unchanged_findings.append(
                change_for(
                    current,
                    previous_severity=previous.severity,
                    current_severity=current.severity,
                )
            )

    for key in sorted(baseline_by_key):
        if key not in comparison_by_key:
            previous = baseline_by_key[key]
            resolved_findings.append(
                change_for(
                    previous,
                    previous_severity=previous.severity,
                    current_severity=None,
                )
            )

    subject_type, subject_id = scan_subject(comparison_scan)
    return ScanComparisonRead(
        target_id=comparison_scan.target_id,
        repository_asset_id=comparison_scan.repository_asset_id,
        subject_type=subject_type,
        subject_id=subject_id,
        baseline_scan_id=baseline_scan.id,
        comparison_scan_id=comparison_scan.id,
        scoring_model_version=SCORING_MODEL_VERSION,
        baseline_score=risk_score_to_read(baseline_score),
        comparison_score=risk_score_to_read(comparison_score),
        score_delta=comparison_score.score - baseline_score.score,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_findings=unchanged_findings,
        severity_changed_findings=severity_changed_findings,
    )


def subject_scans(
    db: Session,
    workspace_id: str,
    *,
    target_id: str | None = None,
    repository_asset_id: str | None = None,
) -> list[Scan]:
    return list(
        db.scalars(
            select(Scan)
            .where(
                Scan.workspace_id == workspace_id,
                Scan.target_id == target_id,
                Scan.repository_asset_id == repository_asset_id,
            )
            .order_by(Scan.created_at.desc())
        ).all()
    )


def findings_for_scans(
    db: Session,
    workspace_id: str,
    scan_ids: list[str],
) -> list[Finding]:
    if not scan_ids:
        return []
    return list(
        db.scalars(
            select(Finding).where(
                Finding.workspace_id == workspace_id,
                Finding.scan_id.in_(scan_ids),
            )
        ).all()
    )


def latest_completed_scans_per_subject_profile(scans: list[Scan]) -> list[Scan]:
    latest: dict[tuple[str, str, str], Scan] = {}
    for scan in sort_completed_scans(scans):
        subject_type, subject_id = scan_subject(scan)
        latest.setdefault((subject_type, subject_id, scan.scan_profile_id), scan)
    return list(latest.values())


def effective_posture_findings(db: Session, scans: list[Scan]) -> list[Finding]:
    findings = findings_for_scans(db, scans[0].workspace_id, [scan.id for scan in scans]) if scans else []
    scans_by_id = {scan.id: scan for scan in scans}
    visible: list[Finding] = []
    for finding in findings:
        scan = scans_by_id.get(finding.scan_id)
        if scan is None:
            continue
        occurrence = occurrence_state_for_read(db, finding, scan)
        lifecycle_status = occurrence.lifecycle_status if occurrence is not None else "open"
        if occurrence is not None and occurrence.suppressed:
            continue
        if lifecycle_status in {"resolved", "false_positive", "suppressed"}:
            continue
        visible.append(finding)
    return visible


def posture_score_to_read(findings: list[Finding], scans: list[Scan]) -> RiskScoreRead | None:
    if not scans:
        return None
    scans_by_id = {scan.id: scan for scan in scans}
    subject_findings = [
        (scan_subject(scans_by_id[finding.scan_id])[1], finding)
        for finding in findings
        if finding.scan_id in scans_by_id
    ]
    calculated = calculate_posture_risk_score(subject_findings)
    latest_at = max((scan.completed_at or scan.created_at for scan in scans), default=scans[0].created_at)
    return RiskScoreRead(
        id="dynamic-posture",
        target_id=None,
        repository_asset_id=None,
        scan_id=None,
        scoring_model_version=calculated.scoring_model_version,
        score=calculated.score,
        label=calculated.label,
        input_summary=calculated.input_summary,
        created_at=latest_at,
    )


def scan_summaries(
    db: Session,
    scans: list[Scan],
    target_lookup: dict[str, Target],
    repository_lookup: dict[str, RepositoryAsset],
) -> list[DashboardScanSummaryRead]:
    summaries: list[DashboardScanSummaryRead] = []
    for scan in scans:
        subject_type, subject_id = scan_subject(scan)
        subject = (
            target_lookup.get(subject_id)
            if subject_type == "web_target"
            else repository_lookup.get(subject_id)
        )
        if subject is None:
            continue
        risk_score: RiskScore | None = None
        if scan.status in COMPLETED_SCAN_STATUSES:
            findings = findings_for_scans(db, scan.workspace_id, [scan.id])
            risk_score = read_scan_risk_score(db, scan, findings)
        summaries.append(
            DashboardScanSummaryRead(
                id=scan.id,
                target_id=scan.target_id,
                repository_asset_id=scan.repository_asset_id,
                subject_type=subject_type,
                subject_id=subject_id,
                target_name=subject.name,
                scan_profile_id=scan.scan_profile_id,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                risk_score=risk_score_to_read(risk_score),
            )
        )
    return summaries


def scan_subject(scan: Scan) -> tuple[str, str]:
    if scan.target_id is not None and scan.repository_asset_id is None:
        return "web_target", scan.target_id
    if scan.repository_asset_id is not None and scan.target_id is None:
        return "repository_asset", scan.repository_asset_id
    raise RuntimeError("Scan must have exactly one authorized subject.")


def get_target_or_404(db: Session, target_id: str, workspace_id: str) -> Target:
    target = db.scalar(
        select(Target).where(
            Target.id == target_id,
            Target.workspace_id == workspace_id,
            Target.archived_at.is_(None),
        )
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found.")
    return target


def get_repository_asset_or_404(
    db: Session,
    repository_asset_id: str,
    workspace_id: str,
) -> RepositoryAsset:
    asset = db.scalar(
        select(RepositoryAsset).where(
            RepositoryAsset.id == repository_asset_id,
            RepositoryAsset.workspace_id == workspace_id,
            RepositoryAsset.archived_at.is_(None),
        )
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository asset not found.",
        )
    return asset


def get_completed_scan_or_404(db: Session, scan_id: str, workspace_id: str) -> Scan:
    scan = db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == workspace_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    if scan.status not in COMPLETED_SCAN_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Risk scores require a completed scan.",
        )
    return scan


def comparison_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="At least two completed scans using the same audit profile are required for comparison.",
    )


def targets_by_id(targets: list[Target]) -> dict[str, Target]:
    return {target.id: target for target in targets}


def repository_assets_by_id(
    repository_assets: list[RepositoryAsset],
) -> dict[str, RepositoryAsset]:
    return {asset.id: asset for asset in repository_assets}


@overload
def risk_score_to_read(score: RiskScore) -> RiskScoreRead: ...


@overload
def risk_score_to_read(score: None) -> None: ...


def risk_score_to_read(score: RiskScore | None) -> RiskScoreRead | None:
    return RiskScoreRead.model_validate(score) if score is not None else None


def sort_completed_scans(scans: list[Scan]) -> list[Scan]:
    return sorted(
        scans,
        key=lambda scan: (
            scan.completed_at or scan.created_at,
            scan.created_at,
            scan.id,
        ),
        reverse=True,
    )


def findings_for_scan(findings: list[Finding], scan_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.scan_id == scan_id]


def finding_map(findings: list[Finding]) -> dict[str, Finding]:
    return {finding.dedupe_key: finding for finding in dedupe_findings(findings)}


def posture_severity_counts(findings: list[Finding], scans: list[Scan]) -> dict[str, int]:
    subject_findings = posture_findings_by_subject(findings, scans)
    counts = Counter(
        finding.severity for _, finding in dedupe_findings_by_subject(subject_findings)
    )
    return ordered_severity_counts(counts)


def posture_finding_count(findings: list[Finding], scans: list[Scan]) -> int:
    return len(dedupe_findings_by_subject(posture_findings_by_subject(findings, scans)))


def posture_findings_by_subject(
    findings: list[Finding],
    scans: list[Scan],
) -> list[tuple[str, Finding]]:
    scans_by_id = {scan.id: scan for scan in scans}
    return [
        (scan_subject(scans_by_id[finding.scan_id])[1], finding)
        for finding in findings
        if finding.scan_id in scans_by_id
    ]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in dedupe_findings(findings))
    return ordered_severity_counts(counts)


def historical_severity_counts(findings: list[Finding]) -> dict[str, int]:
    return ordered_severity_counts(Counter(finding.severity for finding in findings))


def ordered_severity_counts(counts: Counter[str]) -> dict[str, int]:
    return {
        severity: counts.get(severity, 0)
        for severity in ("critical", "high", "medium", "low", "info")
    }


def change_for(
    finding: Finding,
    *,
    previous_severity: str | None,
    current_severity: str | None,
) -> FindingChangeRead:
    return FindingChangeRead(
        dedupe_key=finding.dedupe_key,
        title=finding.title,
        source_tool=finding.source_tool,
        location=finding.affected_url or finding.affected_file,
        previous_severity=previous_severity,
        current_severity=current_severity,
    )
