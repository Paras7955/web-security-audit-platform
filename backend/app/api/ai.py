from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.service import AiExplanationError, AiExplanationResult, AiRateLimitExceeded, generate_ai_explanations
from app.api.deps import get_current_principal, get_db
from app.api.schemas import AiExplanationGroupRead, AiExplanationRead, FindingExplanationRead
from app.core.config import settings
from app.models import Scan
from app.security.auth import AuthenticatedPrincipal

router = APIRouter(tags=["ai"])


@router.get("/scans/{scan_id}/ai-explanations", response_model=AiExplanationRead)
def get_ai_explanations(
    scan_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AiExplanationRead:
    if db.scalar(select(Scan).where(Scan.id == scan_id, Scan.workspace_id == principal.workspace_id)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    try:
        result = generate_ai_explanations(
            db,
            scan_id=scan_id,
            workspace_id=principal.workspace_id,
            user_id=principal.user_id,
            action="interactive_ai_explanations",
            provider_name=settings.ai_provider,
            openai_api_key=settings.openai_api_key,
            openai_model=settings.openai_model,
        )
    except AiExplanationError as exc:
        raise ai_error(exc) from exc
    return to_ai_read(result)


def to_ai_read(result: AiExplanationResult) -> AiExplanationRead:
    return AiExplanationRead(
        scan_id=result.scan_id,
        provider=result.provider,
        fallback_used=result.fallback_used,
        provider_error=result.provider_error,
        summary=result.summary,
        executive_summary=result.executive_summary,
        risk_score_explanation=result.risk_score_explanation,
        scoring_model_version=result.scoring_model_version,
        input_fingerprint=result.input_fingerprint,
        cache_hit=result.cache_hit,
        groups=[
            AiExplanationGroupRead(label=group.label, count=group.count, finding_ids=list(group.finding_ids))
            for group in result.groups
        ],
        explanations=[
            FindingExplanationRead(
                finding_id=explanation.finding_id,
                priority=explanation.priority,
                summary=explanation.summary,
                why_it_matters=explanation.why_it_matters,
                recommended_action=explanation.recommended_action,
                owasp_mapping=explanation.owasp_mapping,
                limitations=explanation.limitations,
            )
            for explanation in result.explanations
        ],
    )


def ai_error(error: AiExplanationError) -> HTTPException:
    detail = str(error)
    if detail == "Scan not found.":
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    if isinstance(error, AiRateLimitExceeded):
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
