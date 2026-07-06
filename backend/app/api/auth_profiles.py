from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_principal, get_db
from app.api.schemas import AuthProfileCreate, AuthProfileRead
from app.auth_profiles import AuthProfileError, encrypt_secret, secret_hint, validate_profile_input
from app.models import AuthProfile
from app.security.auth import AuthenticatedPrincipal


router = APIRouter(prefix="/auth-profiles", tags=["auth-profiles"])


@router.post("", response_model=AuthProfileRead, status_code=status.HTTP_201_CREATED)
def create_auth_profile(
    payload: AuthProfileCreate,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    try:
        profile_type, header_name, secret = validate_profile_input(
            profile_type=payload.profile_type,
            header_name=payload.header_name,
            secret=payload.secret,
        )
        encrypted_secret = encrypt_secret(secret)
    except AuthProfileError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    profile = AuthProfile(
        id=str(uuid4()),
        workspace_id=principal.workspace_id,
        created_by_user_id=principal.user_id,
        label=payload.label.strip(),
        profile_type=profile_type,
        header_name=header_name,
        encrypted_secret=encrypted_secret,
        secret_hint=secret_hint(secret),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.get("", response_model=list[AuthProfileRead])
def list_auth_profiles(
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> list[AuthProfileRead]:
    return list(
        db.scalars(
            select(AuthProfile)
            .where(AuthProfile.workspace_id == principal.workspace_id)
            .order_by(AuthProfile.created_at.desc())
        ).all()
    )


@router.get("/{auth_profile_id}", response_model=AuthProfileRead)
def get_auth_profile(
    auth_profile_id: str,
    principal: AuthenticatedPrincipal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> AuthProfileRead:
    profile = db.scalar(select(AuthProfile).where(AuthProfile.id == auth_profile_id, AuthProfile.workspace_id == principal.workspace_id))
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Auth profile not found.")
    return profile
