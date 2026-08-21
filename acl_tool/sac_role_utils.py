from __future__ import annotations

import re

from .api_utils import first, unique
from .config import (
    CANDIDATE_REVIEW_KEYWORDS,
    ROLE_ALIASES,
    SENSITIVE_SELECTED_ROLE_RULES,
    SUPERUSER_EXPIRY_DAYS,
    USER_EXPIRY_DAYS,
)
from .models import Role, RoleInfo


def to_role(obj: dict) -> Role:
    return Role(
        uuid=first(obj, "uuid", "serverRoleUuid", "roleUuid"),
        name=first(obj, "name", "roleName", "serverRoleName"),
    )


def parse_role_name(role_name: str) -> RoleInfo:
    name = role_name.lower()
    if name.startswith("gcp-"):
        csp = "gcp"
    elif name.startswith("aws-"):
        csp = "aws"
    elif name.startswith("azure-"):
        csp = "azure"
    else:
        csp = "unknown"

    env = "unknown"
    for token in ("preprod", "prod", "devops", "dev", "stg", "qa", "test"):
        if f"-{token}-" in name or f"_{token}_" in name:
            env = token
            break

    if "superuser" in name:
        role_type = "superuser"
    elif re.search(r"(^|[-_])user([-_]|$)", name):
        role_type = "user"
    else:
        role_type = "unknown"

    match = re.search(r"\(([^()]*)\)", role_name)
    hint = match.group(1).strip() if match else ""
    return RoleInfo(csp=csp, env=env, role_type=role_type, hint=hint)


def role_search_terms(keyword: str) -> list[str]:
    keyword = keyword.strip()
    low = keyword.lower()
    terms = [keyword]
    if low in ROLE_ALIASES:
        terms.extend(ROLE_ALIASES[low])
    if re.fullmatch(r"[0-9a-fA-F]{8,32}", keyword):
        terms.append("vpc-" + keyword)
    if low.endswith("-sg"):
        base = keyword[:-3]
        terms.extend([base + "-User-Role", base + "-SuperUser-Role", base + "-Superuser-policy"])
    if "-" in keyword and not low.endswith("-role"):
        terms.extend([f"({keyword})", keyword.replace("_", "-")])
    return unique(terms)


def role_resource_key(role: Role) -> str:
    info = parse_role_name(role.name)
    if info.hint:
        return info.hint
    match = re.search(r"\b(vpc-[0-9a-fA-F-]+)\b", role.name)
    return match.group(1) if match else "-"


def role_warning_label(role: Role) -> str:
    return "주의" if selected_role_sensitive_rule(role) else ""


def candidate_review_required(roles: list[Role]) -> tuple[bool, list[str]]:
    if len(roles) <= 1:
        return False, []
    reasons: list[str] = []
    if len(roles) > 2:
        reasons.append("후보 역할이 2개를 초과합니다.")
    role_types, envs, hints, special_hits = set(), set(), set(), set()
    for role in roles:
        info = parse_role_name(role.name)
        role_types.add(info.role_type)
        if info.env != "unknown":
            envs.add(info.env)
        if info.hint:
            hints.add(info.hint)
        for word in CANDIDATE_REVIEW_KEYWORDS:
            if word in role.name.lower():
                special_hits.add(word)
    if role_types - {"user", "superuser"}:
        reasons.append("User/SuperUser 외 역할 유형이 포함되어 있습니다.")
    if len(envs) > 1:
        reasons.append("여러 env 후보가 확인됩니다: " + ", ".join(sorted(envs)))
    if len(hints) > 1:
        reasons.append("여러 vpc/project 후보가 확인됩니다.")
    if special_hits:
        reasons.append("특수 역할 키워드가 포함되어 있습니다: " + ", ".join(sorted(special_hits)))
    return bool(reasons), reasons


def selected_role_sensitive_rule(role: Role) -> dict | None:
    name = role.name.lower()
    for rule in SENSITIVE_SELECTED_ROLE_RULES:
        if all(item in name for item in rule["include"]) and not any(item in name for item in rule["exclude"]):
            return rule
    return None


def role_candidate_search_text(role: Role) -> str:
    info = parse_role_name(role.name)
    return " ".join([role.name, role_resource_key(role), info.csp, info.env, info.role_type, info.hint, role.uuid]).lower()


def filter_roles_in_memory(roles: list[Role], keyword: str) -> list[Role]:
    terms = [item.lower() for item in re.split(r"\s+", keyword.strip()) if item.strip()]
    if not terms:
        return roles
    return [role for role in roles if all(term in role_candidate_search_text(role) for term in terms)]


def role_expiry_days(role: Role) -> int:
    return SUPERUSER_EXPIRY_DAYS if parse_role_name(role.name).role_type == "superuser" else USER_EXPIRY_DAYS


def role_expiry_label(role: Role) -> str:
    return "SuperUser 기본 90일" if parse_role_name(role.name).role_type == "superuser" else "User 기본 1년"


def role_csp_label(role: Role) -> str:
    info = parse_role_name(role.name)
    return info.csp.upper() if info.csp != "unknown" else ""


def role_type_label(role: Role) -> str:
    role_type = parse_role_name(role.name).role_type
    if role_type == "superuser":
        return "SuperUser"
    if role_type == "user":
        return "User"
    return ""
