import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import User
from .users import sync_user

settings = get_settings()
bearer = HTTPBearer(auto_error=False)
_jwks = PyJWKClient(settings.jwks_url, cache_keys=True, lifespan=3600)

ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def decode_access_token(token: str) -> dict:
    """Verify signature, issuer, audience and expiry of an Authentik JWT."""
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.oidc_client_id,
            issuer=settings.issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError:
        raise _unauthorized("Invalid or expired token")


def _provision_from_userinfo(db: Session, token: str) -> User:
    """First API call by a user who never used the web login: fetch claims once."""
    resp = httpx.get(
        f"{settings.authentik_base_url}/application/o/userinfo/",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if resp.status_code != 200:
        raise _unauthorized("Token rejected by Authentik")
    return sync_user(db, resp.json())


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    user = None
    if creds:  # API client with a Bearer token
        claims = decode_access_token(creds.credentials)
        user = db.scalar(select(User).where(User.sub == claims["sub"]))
        if user is None:
            user = _provision_from_userinfo(db, creds.credentials)
    elif (user_id := request.session.get("user_id")):  # browser session
        user = db.get(User, user_id)

    if user is None:
        raise _unauthorized()
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    return user


def user_rank(user: User) -> int:
    return max((ROLE_RANK.get(r, 0) for r in user.role_names), default=0)


def require_role(minimum: str):
    needed = ROLE_RANK[minimum]

    def checker(user: User = Depends(get_current_user)) -> User:
        if user_rank(user) < needed:
            raise HTTPException(status_code=403, detail=f"Requires role '{minimum}' or higher")
        return user

    return checker
def requires_permissions(*required_permissions: str):
    if not required_permissions:
        raise ValueError("At least one permission is required")

    def checker(user: User = Depends(get_current_user)) -> User:
        missing = set(required_permissions) - user.permission_names
        if missing:
            names = ", ".join(sorted(missing))
            raise HTTPException(
                status_code=403,
                detail=f"Missing required permission(s): {names}",
            )
        return user

    return checker