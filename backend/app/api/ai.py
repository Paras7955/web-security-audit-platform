from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.ai.service import AiExplanationError, AiExplanationResult, generate_ai_explanations
from app.api.deps import get_db
from app.api.schemas import AiExplanationGroupRead, AiExplanationRead, FindingExplanationRead
from app.core.config import settings

router = APIRouter(tags=["ai"])


@router.get("/scans/{scan_id}/ai-explanations", response_model=AiExplanationRead)
def get_ai_explanations(scan_id: str, db: Session = Depends(get_db)) -> AiExplanationRead:
    try:
        result = generate_ai_explanations(
            db,
            scan_id=scan_id,
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
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
