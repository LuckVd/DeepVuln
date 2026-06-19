"""Authentication API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.web.api.deps import get_db
from src.web.core.config import get_security_settings
from src.web.models.user import User
from src.web.services.auth_service import (
    authenticate,
    change_password,
    create_access_token,
    seed_default_user,
)
from src.web.core.security import get_current_user
from src.web.core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool
    username: str
    user_id: int


class ChangePasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=6)


class UserInfoResponse(BaseModel):
    id: int
    username: str
    must_change_password: bool
    is_active: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT token."""
    settings = get_security_settings()

    if not settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication is disabled",
        )

    user = await authenticate(db, body.username, body.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        user_id=user.id,
        must_change_password=user.must_change_password,
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expire_minutes=settings.jwt_expire_minutes,
    )

    return LoginResponse(
        access_token=token,
        must_change_password=user.must_change_password,
        username=user.username,
        user_id=user.id,
    )


@router.post("/change-password")
async def change_password_endpoint(
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the current user's password."""
    await change_password(db, current_user.id, request.new_password)

    # Issue a new token with must_change_password=False
    settings = get_security_settings()
    new_token = create_access_token(
        user_id=current_user.id,
        must_change_password=False,
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        expire_minutes=settings.jwt_expire_minutes,
    )

    return {"message": "Password changed successfully", "access_token": new_token}


@router.get("/me", response_model=UserInfoResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return UserInfoResponse(
        id=current_user.id,
        username=current_user.username,
        must_change_password=current_user.must_change_password,
        is_active=current_user.is_active,
    )


@router.post("/seed")
async def seed_user(db: AsyncSession = Depends(get_db)):
    """Manually trigger default user seeding (for testing/setup)."""
    await seed_default_user(db)
    return {"message": "Seed complete"}
