from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Role, User, Permission

# Authentik group name -> our application's role name 
GROUP_TO_ROLE = {
    "app-admin": "admin",
    "app-editor": "editor",
    "app-viewer": "viewer",
}


ROLE_PERMISSIONS = {
    "viewer": {"articles:read"},
    "editor": {"articles:read", "articles:create"},
    "admin": {"articles:read", "articles:create", "users:list"},
}


def seed_roles(db: Session) -> None:
    roles = {role.name: role for role in db.scalars(select(Role))}

    for role_name in ROLE_PERMISSIONS:
        if role_name not in roles:
            role = Role(name=role_name)
            db.add(role)
            roles[role_name] = role

    db.flush()

    permission_names = set().union(*ROLE_PERMISSIONS.values())
    permissions = {
        permission.name: permission
        for permission in db.scalars(select(Permission))
    }

    for permission_name in permission_names - permissions.keys():
        permission = Permission(name=permission_name)
        db.add(permission)
        permissions[permission_name] = permission

    db.flush()

    for role_name, names in ROLE_PERMISSIONS.items():
        roles[role_name].permissions = [
            permissions[name] for name in sorted(names)
        ]

    db.commit()

# def seed_roles(db: Session) -> None:
#     existing = set(db.scalars(select(Role.name)))
#     for name in GROUP_TO_ROLE.values():
#         if name not in existing:
#             db.add(Role(name=name))
#     db.commit()


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