from __future__ import annotations

import csv
import os
from collections import defaultdict

from .asset_tags import AssetIdentity, TagPair, normalize_asset_identity, normalize_key
from .config import (
    LOCAL_OBJECT_REFERENCE_FILES,
    LOCAL_TAG_REFERENCE_FILES,
    USE_LOCAL_OBJECT_REFERENCE_CSV,
    USE_LOCAL_TAG_REFERENCE_CSV,
)
from .models import DacConnection, KacRole, Role


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resolve_reference_path(path: str) -> str:
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(repo_root(), path))


def read_csv_rows(path: str) -> list[dict[str, str]]:
    resolved = resolve_reference_path(path)
    if not resolved or not os.path.exists(resolved):
        return []
    with open(resolved, "r", encoding="utf-8-sig", newline="") as f:
        return [{str(k or "").strip(): str(v or "").strip() for k, v in row.items()} for row in csv.DictReader(f)]


def bool_from_db(value: str) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "y", "yes")


def value_not_null(value: str) -> str:
    text = str(value or "").strip()
    return "" if text.upper() == "NULL" else text


def normalize_database_type(value: str) -> str:
    norm = normalize_key(value)
    if norm == "customdatasource":
        return "CUSTOM"
    mapping = {
        "mysql": "MYSQL",
        "mariadb": "MARIADB",
        "postgresql": "POSTGRESQL",
        "postgres": "POSTGRESQL",
        "redshift": "REDSHIFT",
        "redis": "REDIS",
        "valkey": "REDIS",
        "mongodb": "MONGODB",
        "documentdb": "DOCUMENTDB",
        "oracle": "ORACLE",
        "hana": "HANA",
        "bigquery": "BIGQUERY",
        "dynamodb": "DYNAMODB",
    }
    return mapping.get(norm, value.upper())


def endpoint_from_cluster(row: dict[str, str]) -> str:
    host = value_not_null(row.get("host", ""))
    port = value_not_null(row.get("port", ""))
    if host and port and f":{port}" not in host:
        return f"{host}:{port}"
    return host


def tag_rows_to_pairs(rows: list[dict[str, str]]) -> list[TagPair]:
    pairs: list[TagPair] = []
    for row in rows:
        key = row.get("tag_key") or row.get("key") or row.get("tagKey") or ""
        value = row.get("tag_value") or row.get("value") or row.get("tagValue") or ""
        if key or value:
            pairs.append(TagPair(key=key, value=value, source="csv"))
    return pairs


class LocalAssetReference:
    """권한 플랫폼 객체 UUID와 태그를 읽는 read-only CSV 인덱스입니다.

    이 클래스는 파일을 쓰지 않고 성공 여부도 판단하지 않습니다. 인터랙티브
    흐름에 빠른 후보만 넘겨주며, 실제 변경과 검증 기준은 항상 API입니다.
    """

    def __init__(
        self,
        object_enabled: bool | None = None,
        tag_enabled: bool | None = None,
    ):
        self.object_enabled = USE_LOCAL_OBJECT_REFERENCE_CSV if object_enabled is None else object_enabled
        self.tag_enabled = USE_LOCAL_TAG_REFERENCE_CSV if tag_enabled is None else tag_enabled
        self._dac_groups: dict[str, dict[str, str]] | None = None
        self._dac_groups_by_id: dict[str, dict[str, str]] | None = None
        self._dac_clusters_by_group_uuid: dict[str, list[DacConnection]] | None = None
        self._tag_assets: dict[str, list[AssetIdentity]] = {}

    def dac_groups(self) -> dict[str, dict[str, str]]:
        if self._dac_groups is not None:
            return self._dac_groups
        rows = read_csv_rows(LOCAL_OBJECT_REFERENCE_FILES.get("dac_cluster_groups", ""))
        self._dac_groups = {row.get("uuid", ""): row for row in rows if row.get("uuid")}
        self._dac_groups_by_id = {row.get("id", ""): row for row in rows if row.get("id")}
        return self._dac_groups

    def dac_groups_by_id(self) -> dict[str, dict[str, str]]:
        self.dac_groups()
        return self._dac_groups_by_id or {}

    def dac_clusters_by_group_uuid(self) -> dict[str, list[DacConnection]]:
        if self._dac_clusters_by_group_uuid is not None:
            return self._dac_clusters_by_group_uuid
        groups_by_id = self.dac_groups_by_id()
        clusters = read_csv_rows(LOCAL_OBJECT_REFERENCE_FILES.get("dac_clusters", ""))
        result: dict[str, list[DacConnection]] = defaultdict(list)
        for cluster in clusters:
            if bool_from_db(cluster.get("deleted", "")):
                continue
            group = groups_by_id.get(cluster.get("group_id", ""))
            if not group or bool_from_db(group.get("deleted", "")):
                continue
            group_uuid = group.get("uuid", "")
            cluster_uuid = cluster.get("uuid", "")
            if not group_uuid or not cluster_uuid:
                continue
            database_type = normalize_database_type(group.get("db_type", ""))
            endpoint = endpoint_from_cluster(cluster)
            result[group_uuid].append(
                DacConnection(
                    uuid=cluster_uuid,
                    name=value_not_null(group.get("name", "")) or cluster_uuid,
                    database_type=database_type,
                    connection_uuid=group_uuid,
                    cloud_provider_type=infer_csp_from_text(" ".join(group.values())),
                    endpoints=[endpoint] if endpoint else [],
                    cluster_type=value_not_null(cluster.get("repl_type", "")) or "SINGLE",
                    deleted=False,
                )
            )
        self._dac_clusters_by_group_uuid = dict(result)
        return self._dac_clusters_by_group_uuid

    def dac_connection_clusters(self, group_uuid: str) -> list[DacConnection]:
        if not self.object_enabled:
            return []
        return list(self.dac_clusters_by_group_uuid().get(group_uuid, []))

    def dac_connection_reference(self, target: DacConnection) -> DacConnection | None:
        """선택한 DAC DB 대상과 같은 CSV cluster row를 반환합니다."""

        if not self.object_enabled:
            return None
        for clusters in self.dac_clusters_by_group_uuid().values():
            for connection in clusters:
                if connection.uuid == target.uuid:
                    return connection
        return None

    def search_dac_connections(self, keyword: str) -> list[DacConnection]:
        if not self.object_enabled:
            return []
        needle = keyword.lower().strip()
        if not needle:
            return []
        tags_by_uuid = self.dac_tag_rows_by_uuid()
        found: dict[str, DacConnection] = {}
        for group_uuid, clusters in self.dac_clusters_by_group_uuid().items():
            group = self.dac_groups().get(group_uuid, {})
            tag_text = " ".join(f"{row.get('tag_key', '')} {row.get('tag_value', '')}" for row in tags_by_uuid.get(group_uuid, []))
            for connection in clusters:
                fields = [
                    group_uuid,
                    connection.uuid,
                    connection.name,
                    connection.database_type,
                    value_not_null(group.get("cloud_identifier", "")),
                    value_not_null(group.get("network_id", "")),
                    " ".join(connection.endpoints or []),
                    tag_text,
                ]
                if needle in " ".join(fields).lower():
                    found[connection.uuid] = connection
        return list(found.values())

    def search_sac_roles(self, keyword: str) -> list[Role]:
        if not self.object_enabled:
            return []
        needle = keyword.lower().strip()
        if not needle:
            return []
        roles: dict[str, Role] = {}
        for row in read_csv_rows(LOCAL_OBJECT_REFERENCE_FILES.get("sac_roles", "")):
            uuid = first_row_value(row, "uuid", "role_uuid", "serverRoleUuid", "server_role_uuid")
            name = first_row_value(row, "name", "role_name", "serverRoleName", "server_role_name")
            if not uuid or not name:
                continue
            if needle in " ".join(row.values()).lower():
                roles[uuid] = Role(uuid=uuid, name=name)
        return list(roles.values())

    def sac_role_reference(self, target: Role) -> Role | None:
        """선택한 SAC role과 같은 CSV row가 있으면 반환합니다."""

        if not self.object_enabled:
            return None
        for row in read_csv_rows(LOCAL_OBJECT_REFERENCE_FILES.get("sac_roles", "")):
            uuid = first_row_value(row, "uuid", "role_uuid", "serverRoleUuid", "server_role_uuid")
            name = first_row_value(row, "name", "role_name", "serverRoleName", "server_role_name")
            if not uuid or not name:
                continue
            if uuid == target.uuid or name.lower() == target.name.lower():
                return Role(uuid=uuid, name=name)
        return None

    def list_kac_roles(self) -> list[KacRole]:
        if not self.object_enabled:
            return []
        roles: dict[str, KacRole] = {}
        for row in read_csv_rows(LOCAL_OBJECT_REFERENCE_FILES.get("kac_roles", "")):
            uuid = first_row_value(row, "uuid", "role_uuid", "roleUuid")
            name = first_row_value(row, "name", "role_name", "roleName")
            if not uuid or not name:
                continue
            description = first_row_value(row, "description", "role_description", "roleDescription")
            policies = split_list_value(first_row_value(row, "policies", "assigned_policies", "assignedPolicies"))
            roles[uuid] = KacRole(uuid=uuid, name=name, description=description, policies=policies)
        return list(roles.values())

    def kac_role_reference(self, target: KacRole) -> KacRole | None:
        """선택한 KAC role과 같은 CSV row가 있으면 반환합니다."""

        if not self.object_enabled:
            return None
        for role in self.list_kac_roles():
            if role.uuid == target.uuid or role.name.lower() == target.name.lower():
                return role
        return None

    def search_kac_roles(self, keyword: str) -> list[KacRole]:
        needle = keyword.lower().strip()
        if not needle:
            return []
        return [role for role in self.list_kac_roles() if needle in " ".join([
            role.uuid,
            role.name,
            role.description,
            " ".join(role.policies or []),
        ]).lower()]

    def tag_assets(self, scope: str) -> list[AssetIdentity]:
        if not self.tag_enabled:
            return []
        scope = scope.lower()
        if scope in self._tag_assets:
            return self._tag_assets[scope]
        if scope == "dac":
            assets = self.load_dac_tag_assets()
        elif scope == "sac":
            assets = self.load_sac_tag_assets()
        elif scope == "kac":
            assets = self.load_kac_tag_assets()
        else:
            assets = []
        self._tag_assets[scope] = assets
        return assets

    def dac_tag_rows_by_uuid(self) -> dict[str, list[dict[str, str]]]:
        rows = read_csv_rows(LOCAL_TAG_REFERENCE_FILES.get("dac", ""))
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            uuid = row.get("cluster_group_uuid") or row.get("connection_uuid") or row.get("uuid") or ""
            if uuid:
                grouped[uuid].append(row)
        return dict(grouped)

    def load_dac_tag_assets(self) -> list[AssetIdentity]:
        grouped = self.dac_tag_rows_by_uuid()
        groups = self.dac_groups()
        assets: list[AssetIdentity] = []
        for group_uuid, rows in grouped.items():
            group = groups.get(group_uuid, {})
            tags = tag_rows_to_pairs(rows)
            obj = {
                "uuid": group_uuid,
                "name": value_not_null(group.get("name", "")) or group_uuid,
                "databaseType": normalize_database_type(group.get("db_type", "")),
                "cloudProviderType": infer_csp_from_text(" ".join(group.values() or [])),
                "description": value_not_null(group.get("cloud_identifier", "")),
                "tags": [{"key": tag.key, "value": tag.value} for tag in tags],
            }
            assets.append(normalize_asset_identity("DAC", "db-connection", obj))
        return assets

    def load_sac_tag_assets(self) -> list[AssetIdentity]:
        rows = read_csv_rows(LOCAL_TAG_REFERENCE_FILES.get("sac", ""))
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            uuid = row.get("server_group_uuid") or row.get("uuid") or ""
            if uuid:
                grouped[uuid].append(row)
        assets: list[AssetIdentity] = []
        for uuid, tag_rows in grouped.items():
            tags = tag_rows_to_pairs(tag_rows)
            obj = {
                "uuid": uuid,
                "name": uuid,
                "filterTags": [
                    {
                        "key": row.get("tag_key", ""),
                        "operator": row.get("tag_operator", ""),
                        "value": row.get("tag_value", ""),
                    }
                    for row in tag_rows
                ],
                "tags": [{"key": tag.key, "value": tag.value} for tag in tags],
            }
            assets.append(normalize_asset_identity("SAC", "server-group", obj))
        return assets

    def load_kac_tag_assets(self) -> list[AssetIdentity]:
        rows = read_csv_rows(LOCAL_TAG_REFERENCE_FILES.get("kac", ""))
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            uuid = row.get("cluster_uuid") or row.get("uuid") or ""
            if uuid:
                grouped[uuid].append(row)
        assets: list[AssetIdentity] = []
        for uuid, tag_rows in grouped.items():
            tags = tag_rows_to_pairs(tag_rows)
            obj = {
                "uuid": uuid,
                "name": uuid,
                "tags": [{"key": tag.key, "value": tag.value} for tag in tags],
            }
            assets.append(normalize_asset_identity("KAC", "cluster", obj))
        return assets


def infer_csp_from_text(text: str) -> str:
    lower = text.lower()
    if "aws" in lower or "arn:aws:" in lower:
        return "AWS"
    if "gcp" in lower or "google" in lower:
        return "GCP"
    return ""


def first_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = value_not_null(row.get(key, ""))
        if value:
            return value
    return ""


def split_list_value(value: str) -> list[str]:
    if not value:
        return []
    normalized = value.replace("|", ",").replace(";", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]
