from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Role, User

# Authentik group name -> application role name
GROUP_TO_ROLE = {
    "app-admin": "admin",
    "app-editor": "editor",
    "app-viewer": "viewer",
}


def seed_roles(db: Session) -> None:
    existing = set(db.scalars(select(Role.name)))
    for name in GROUP_TO_ROLE.values():
        if name not in existing:
            db.add(Role(name=name))
    db.commit()


def roles_from_claims(claims: dict) -> set[str]:
    groups = claims.get("groups") or []
    return {GROUP_TO_ROLE[g] for g in groups if g in GROUP_TO_ROLE}


def _get_or_create(db: Session, sub: str) -> User:
    user = db.scalar(select(User).where(User.sub == sub))
    if user:
        return user
    user = User(sub=sub, username=sub)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        # Two first logins raced; the other request created the row.
        db.rollback()
        user = db.scalar(select(User).where(User.sub == sub))
    return user


def sync_user(db: Session, claims: dict) -> User:
    user = _get_or_create(db, claims["sub"])
    user.username = claims.get("preferred_username") or claims.get("email") or claims["sub"]
    user.email = claims.get("email")
    user.name = claims.get("name")
    user.last_login_at = datetime.now(timezone.utc)

    wanted = roles_from_claims(claims)
    user.roles = list(db.scalars(select(Role).where(Role.name.in_(wanted)))) if wanted else []

    db.commit()
    db.refresh(user)
    return user