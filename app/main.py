from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

from .auth_routes import router as auth_router
from .config import get_settings
from .db import Base, SessionLocal, engine, get_db
from .models import User
from .security import get_current_user, require_role
from .users import seed_roles

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_roles(db)
    yield


app = FastAPI(title="Authentik RBAC demo", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.secure_cookies,
    same_site="lax",
    max_age=8 * 3600,
)
app.include_router(auth_router)


@app.exception_handler(StarletteHTTPException)
async def http_errors(request: Request, exc: StarletteHTTPException):
    # Browsers that hit a protected page get sent to login; APIs get JSON.
    if exc.status_code == 401 and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse(f"/login?next={quote(request.url.path)}", status_code=303)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


@app.get("/")
def home():
    return HTMLResponse('<h1>Authentik RBAC demo</h1><p><a href="/login">Log in</a> | <a href="/register">Register</a> | <a href="/me">My profile</a></p><form method="post" action="/logout"><button>Log out</button></form>')


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": sorted(user.role_names),
    }


@app.get("/articles")
def list_articles(user: User = Depends(require_role("viewer"))):
    return {"articles": ["Welcome", "Release notes"], "read_by": user.username}


@app.post("/articles")
def create_article(user: User = Depends(require_role("editor"))):
    return {"created_by": user.username}


@app.get("/admin/users")
def admin_users(
    _: User = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    users = db.scalars(select(User).order_by(User.id))
    return [
        {"id": u.id, "username": u.username, "email": u.email, "roles": sorted(u.role_names)}
        for u in users
    ]