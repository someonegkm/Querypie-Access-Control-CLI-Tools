from __future__ import annotations

import re
from dataclasses import dataclass


AWS_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
GCP_PROJECT_RE = re.compile(r"\b([a-z][a-z0-9-]{4,61}[a-z0-9])\b", re.IGNORECASE)
VPC_RE = re.compile(r"\b(vpc-[0-9a-fA-F]+)\b")

AWS_ACCOUNT_KEYS = {
    "awsaccount",
    "awsaccountid",
    "account",
    "accountid",
    "aws_account",
    "aws_account_id",
    "account_id",
    "cloud_account",
}
GCP_PROJECT_KEYS = {
    "gcpproject",
    "gcpprojectid",
    "project",
    "projectid",
    "project_id",
    "gcp_project",
    "gcp_project_id",
}
CLOUD_PROVIDER_KEYS = {
    "cloudprovider",
    "cloudproviderid",
    "cloudprovidertag",
    "cloud_provider",
    "cloud_provider_id",
    "cloud_provider_tag",
    "cloudprovidername",
    "cloud_provider_name",
    "loudprovidername",
    "loud_provider_name",
}
SERVICE_KEYS = {"service", "system", "application", "app", "서비스", "시스템", "시스템서비스명"}
ENV_KEYS = {"env", "environment", "stage", "환경"}
CSP_KEYS = {"csp", "cloud", "cloudprovider", "cloudprovidertype", "cloud_provider", "cloud_provider_type"}
VPC_KEYS = {"vpc", "vpcid", "vpc_id", "vpcname", "vpc_name"}
ALL_KEYS = {"", "all", "any", "전체", "*"}


@dataclass
class TagPair:
    key: str
    value: str
    source: str = ""


@dataclass
class AssetIdentity:
    product: str
    asset_type: str
    name: str
    uuid: str = ""
    csp: str = ""
    cloudprovider: str = ""
    aws_account_id: str = ""
    gcp_project_id: str = ""
    vpc_id: str = ""
    env: str = ""
    service: str = ""
    tags: list[TagPair] | None = None

    @property
    def cloud_value(self) -> str:
        if self.csp == "AWS":
            return self.aws_account_id
        if self.csp == "GCP":
            return self.gcp_project_id
        return self.aws_account_id or self.gcp_project_id

    @property
    def cloud_tag_key(self) -> str:
        if self.csp == "AWS":
            return "aws_account_id"
        if self.csp == "GCP":
            return "gcp_project_id"
        return "cloud_provider_id"

    @property
    def cloudprovider_value(self) -> str:
        if self.cloudprovider:
            return self.cloudprovider
        if self.csp == "AWS" and self.aws_account_id:
            return f"aws-{self.aws_account_id}"
        if self.csp == "GCP" and self.gcp_project_id:
            return f"gcp-{self.gcp_project_id}"
        return self.cloud_value


def normalize_key(value: str) -> str:
    return re.sub(r"[\s\-_./]+", "", str(value or "").strip().lower())


def clean_value(value) -> str:
    return str(value or "").strip()


def first_non_empty(*values: str) -> str:
    for value in values:
        value = clean_value(value)
        if value:
            return value
    return ""


def extract_tags(obj: dict) -> list[TagPair]:
    """API의 tags/filterTags/cloudProvider tag 형태를 최대한 공통 key/value로 정규화한다."""

    tags: list[TagPair] = []
    for source_key in ("tags", "filterTags", "defaultTags", "cloudProviderTags"):
        values = obj.get(source_key)
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            key = first_non_empty(item.get("key"), item.get("tagKey"), item.get("name"))
            value = first_non_empty(item.get("value"), item.get("tagValue"))
            if key or value:
                tags.append(TagPair(key=key, value=value, source=source_key))

    for key in ("cloudProviderType", "databaseType", "name", "description"):
        if obj.get(key):
            tags.append(TagPair(key=key, value=clean_value(obj.get(key)), source="field"))
    return tags


def find_aws_account(text: str) -> str:
    match = AWS_ACCOUNT_RE.search(text or "")
    return match.group(1) if match else ""


def find_gcp_project(text: str) -> str:
    if not re.search(r"\b(gcp|google|project|projectid|project_id)\b|프로젝트", text or "", re.IGNORECASE):
        return ""
    for match in GCP_PROJECT_RE.finditer(text or ""):
        value = match.group(1)
        lower = value.lower()
        if lower.startswith("vpc-") or re.fullmatch(r"[0-9a-f-]{16,}", lower):
            continue
        if "-" in value and not AWS_ACCOUNT_RE.fullmatch(value):
            return value
    return ""


def find_vpc_id(text: str) -> str:
    match = VPC_RE.search(text or "")
    return match.group(1) if match else ""


def classify_csp(text: str, tags: list[TagPair]) -> str:
    lower = (text or "").lower()
    if "aws" in lower:
        return "AWS"
    if "gcp" in lower or "google" in lower:
        return "GCP"
    for tag in tags:
        key = normalize_key(tag.key)
        value = tag.value.lower()
        if key in CSP_KEYS or "provider" in key:
            if "aws" in value:
                return "AWS"
            if "gcp" in value or "google" in value:
                return "GCP"
    if find_aws_account(text):
        return "AWS"
    if find_gcp_project(text):
        return "GCP"
    return ""


def value_by_key(tags: list[TagPair], aliases: set[str]) -> str:
    for tag in tags:
        if normalize_key(tag.key) in aliases and tag.value:
            return tag.value
    return ""


def values_by_key(tags: list[TagPair], aliases: set[str]) -> list[str]:
    values: list[str] = []
    for tag in tags:
        if normalize_key(tag.key) in aliases and tag.value and tag.value not in values:
            values.append(tag.value)
    return values


def normalize_asset_identity(product: str, asset_type: str, obj: dict) -> AssetIdentity:
    common = obj.get("common") if isinstance(obj, dict) else None
    if isinstance(common, dict):
        merged = dict(common)
        for key, value in obj.items():
            if key != "common" and key not in merged:
                merged[key] = value
        obj = merged

    tags = extract_tags(obj)
    text = " ".join(
        [clean_value(obj.get(key)) for key in ("name", "description", "cloudProviderType", "databaseType")]
        + [f"{tag.key} {tag.value}" for tag in tags]
    )
    csp = classify_csp(text, tags)
    cloudprovider = value_by_key(tags, CLOUD_PROVIDER_KEYS)
    aws_account_id = value_by_key(tags, AWS_ACCOUNT_KEYS) or find_aws_account(text)
    gcp_project_id = value_by_key(tags, GCP_PROJECT_KEYS) or find_gcp_project(text)
    vpc_candidates = values_by_key(tags, VPC_KEYS)
    vpc_id = next((value for value in vpc_candidates if value.lower().startswith("vpc-")), "") or find_vpc_id(text)
    env = value_by_key(tags, ENV_KEYS)
    service = value_by_key(tags, SERVICE_KEYS)

    if not csp and aws_account_id:
        csp = "AWS"
    if not csp and gcp_project_id:
        csp = "GCP"

    return AssetIdentity(
        product=product,
        asset_type=asset_type,
        name=first_non_empty(obj.get("name"), obj.get("connectionName"), obj.get("clusterName")),
        uuid=first_non_empty(obj.get("uuid"), obj.get("clusterUuid")),
        csp=csp,
        cloudprovider=cloudprovider,
        aws_account_id=aws_account_id,
        gcp_project_id=gcp_project_id,
        vpc_id=vpc_id,
        env=env,
        service=service,
        tags=tags,
    )


def asset_matches_keyword(identity: AssetIdentity, keyword: str) -> bool:
    needle = keyword.lower().strip()
    if not needle:
        return False
    fields = [
        identity.product,
        identity.asset_type,
        identity.name,
        identity.uuid,
        identity.csp,
        identity.cloudprovider,
        identity.aws_account_id,
        identity.gcp_project_id,
        identity.vpc_id,
        identity.env,
        identity.service,
    ]
    fields.extend(f"{tag.key} {tag.value}" for tag in identity.tags or [])
    return needle in " ".join(fields).lower()


def asset_matches_key_value(identity: AssetIdentity, key: str, value: str) -> bool:
    """사람이 입력한 tag key/value로 객체를 찾습니다.

    cloudprovider, account, project, vpc, name, type, env, service, csp 같은
    알려진 key는 정규화한 AssetIdentity 필드로 매칭합니다. 모르는 key는
    API에서 받은 원본 tag key와 비교합니다.
    """

    key_norm = normalize_key(key)
    needle = value.lower().strip()
    value_is_all = normalize_key(value) in ALL_KEYS
    if key_norm in ALL_KEYS and value_is_all:
        return True
    if not needle and not value_is_all:
        return False
    if key_norm in ALL_KEYS:
        return asset_matches_keyword(identity, value)

    field_map = {
        "product": [identity.product],
        "assettype": [identity.asset_type],
        "type": [identity.asset_type],
        "name": [identity.name],
        "asset": [identity.name],
        "servergroup": [identity.name],
        "db": [identity.name],
        "cluster": [identity.name],
        "csp": [identity.csp],
        "cloud": [identity.csp],
        "cloudprovider": [identity.cloudprovider, identity.cloudprovider_value],
        "cloudproviderid": [identity.cloudprovider, identity.cloudprovider_value],
        "account": [identity.aws_account_id, identity.cloud_value, identity.cloudprovider_value],
        "accountid": [identity.aws_account_id, identity.cloud_value],
        "aws": [identity.aws_account_id, identity.cloudprovider_value],
        "awsaccount": [identity.aws_account_id],
        "project": [identity.gcp_project_id, identity.cloud_value],
        "projectid": [identity.gcp_project_id],
        "gcp": [identity.gcp_project_id, identity.cloudprovider_value],
        "gcpproject": [identity.gcp_project_id],
        "vpc": [identity.vpc_id],
        "vpcid": [identity.vpc_id],
        "env": [identity.env],
        "environment": [identity.env],
        "service": [identity.service],
        "system": [identity.service],
    }
    if key_norm in field_map:
        if value_is_all:
            return any(item for item in field_map[key_norm])
        return needle in " ".join(field_map[key_norm]).lower()

    for tag in identity.tags or []:
        tag_key = normalize_key(tag.key)
        if key_norm == tag_key or key_norm in tag_key:
            if value_is_all:
                return True
            if needle in tag.value.lower():
                return True
    return False


def suggested_search_terms(identity: AssetIdentity) -> list[str]:
    terms = [
        identity.cloudprovider_value,
        identity.cloud_value,
        identity.service,
        identity.env,
        identity.vpc_id,
        identity.name,
    ]
    return unique([term for term in terms if term])


def tag_summary(identity: AssetIdentity, limit: int = 5) -> str:
    """사람이 식별하기 좋은 태그만 짧게 보여준다."""

    preferred = {
        "cloudprovidername",
        "cloudprovider",
        "accountid",
        "projectid",
        "vpcid",
        "vpc",
        "vpcname",
        "csp",
        "platformorg",
        "platformenv",
        "platformpdps",
    }
    picked: list[str] = []
    rest: list[str] = []
    for tag in identity.tags or []:
        if not tag.key or not tag.value:
            continue
        if normalize_key(tag.key) == "rts":
            continue
        label = f"{tag.key}={tag.value}"
        if label in picked or label in rest:
            continue
        if normalize_key(tag.key) in preferred:
            picked.append(label)
        else:
            rest.append(label)
    return " / ".join((picked + rest)[:limit]) or "-"


def unique(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in result:
            result.append(value)
    return result


def identity_to_row(identity: AssetIdentity, source_file: str = "", ticket: str = "") -> dict[str, str]:
    terms = suggested_search_terms(identity)
    return {
        "source_file": source_file,
        "ticket": ticket,
        "product": identity.product,
        "asset_type": identity.asset_type,
        "asset_name": identity.name,
        "asset_uuid": identity.uuid,
        "csp": identity.csp,
        "cloudprovider": identity.cloudprovider_value,
        "cloud_tag_key": identity.cloud_tag_key,
        "cloud_tag_value": identity.cloud_value,
        "aws_account_id": identity.aws_account_id,
        "gcp_project_id": identity.gcp_project_id,
        "vpc_id": identity.vpc_id,
        "env": identity.env,
        "service": identity.service,
        "suggested_terms": " | ".join(terms),
    }
