from __future__ import annotations

from .api_utils import first
from .config import INTERNAL_DOMAINS, PARTNER_DOMAINS
from .models import User


def classify_domain(email: str) -> str:
    domain = email.split("@")[-1].lower() if "@" in email else ""
    if any(domain.endswith(item) for item in PARTNER_DOMAINS):
        return "partner"
    if any(domain.endswith(item) for item in INTERNAL_DOMAINS):
        return "internal"
    return "unknown"


def to_user(obj: dict) -> User:
    email = first(obj, "email", "userEmail")
    return User(
        uuid=first(obj, "uuid", "userUuid"),
        name=first(obj, "name", "displayName", "username"),
        login_id=first(obj, "loginId", "login_id", "userName"),
        email=email,
        domain_type=classify_domain(email),
    )


def normalize_user_query(keyword: str) -> str:
    return keyword.strip().strip("*")
