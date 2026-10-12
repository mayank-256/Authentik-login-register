from urllib.parse import urlparse

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .users import sync_user  # defined in the next section

settings = get_settings()
router = APIRouter()

oauth = OAuth()
oauth.register(
    name="authentik",
    client_id=settings.oidc_client_id,
    client_secret=settings.oidc_client_secret,
    server_metadata_url=settings.metadata_url,
    client_kwargs={
        "scope": "openid profile email",
        "code_challenge_method": "S256",  # enables PKCE
    },
)


def safe_next(value: str | None) -> str:
    """Only allow same-site relative paths, to prevent open redirects."""
    if not value:
        return "/"
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


@router.get("/login")
async def login(request: Request, next: str = "/"):
    request.session["next"] = safe_next(next)
    return await oauth.authentik.authorize_redirect(request, settings.redirect_uri)


@router.get("/auth/callback", name="auth_callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.authentik.authorize_access_token(request)
    except OAuthError as exc:
        raise HTTPException(status_code=400, detail=f"Login failed: {exc.error}")

    claims = token.get("userinfo")
    if not claims:
        raise HTTPException(status_code=400, detail="No ID token claims returned")

    user = sync_user(db, dict(claims))  # create or update the PostgreSQL user
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    next_url = safe_next(request.session.pop("next", "/"))
    request.session.clear()  # drop the OAuth state, start a fresh session
    request.session["user_id"] = user.id
    return RedirectResponse(next_url, status_code=303)


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    # Also end the Authentik session so "login" actually asks for credentials again
    return RedirectResponse(f"{settings.issuer}end-session/", status_code=303)

@router.get("/register")
async def register():
    url = f"{settings.authentik_base_url}/if/flow/{settings.enrollment_flow_slug}/"
    return RedirectResponse(url)