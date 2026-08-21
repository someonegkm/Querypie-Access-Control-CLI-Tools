from __future__ import annotations

from dataclasses import dataclass

from .config import (
    DAC_CANDIDATE_DISPLAY_LIMIT,
    DAC_DBA_EXPIRY_DAYS,
    DAC_DEFAULT_EXPIRY_DAYS,
    DAC_EXCLUDED_NAME_KEYWORDS,
    DAC_PAGE_SIZE,
    MAX_DAC_CONNECTION_SCAN_PAGES,
)
from .io_utils import read_csv_items, read_defaulted, read_role_keyword, read_value, run_input_steps
from .models import Back, DacConnection, DacPrivilege, User
from .report import ReportWriter, read_report_context
from .resolver import Resolver
from .asset_tags import AssetIdentity, normalize_key
from .asset_reference import LocalAssetReference
from .api_utils import (
    end_of_day_utc,
    first,
    inclusive_expiry_date,
    is_full_search,
    normalize_search_key,
    page_numbers,
    parse_number_selection,
    quote,
    response_list,
    warn_scan_limit,
)
from .view import ConsoleView


def dac_permission_kind(privilege: DacPrivilege) -> str:
    name = privilege.name.lower()
    if "dba" in name:
        return "DBA"
    if "rw" in name or "write" in name:
        return "RW"
    if "ro" in name or "read" in name:
        return "RO"
    return privilege.name


def default_dac_expiry(privilege: DacPrivilege) -> str:
    days = DAC_DBA_EXPIRY_DAYS if dac_permission_kind(privilege) == "DBA" else DAC_DEFAULT_EXPIRY_DAYS
    return inclusive_expiry_date(days)


def dac_expiry_at(expiry: str) -> str:
    # API는 UTC date-time을 요구합니다.
    # 입력한 날짜의 마지막 시각까지 권한이 유지되도록 맞춥니다.
    return end_of_day_utc(expiry)


@dataclass
class DacAssignedPermission:
    user: User
    connection: DacConnection
    privilege: DacPrivilege
    status: str


def to_dac_connection(obj: dict) -> DacConnection:
    return DacConnection(
        uuid=str(obj.get("uuid") or ""),
        name=str(obj.get("name") or ""),
        database_type=str(obj.get("databaseType") or ""),
        connection_uuid=str(obj.get("uuid") or ""),
        cloud_provider_type=str(obj.get("cloudProviderType") or ""),
        endpoints=[],
        deleted=bool(obj.get("deleted")),
    )


def to_dac_privilege(obj: dict) -> DacPrivilege:
    return DacPrivilege(
        uuid=str(obj.get("uuid") or ""),
        name=str(obj.get("name") or ""),
        vendor=str(obj.get("privilegeVendor") or ""),
        status=str(obj.get("status") or ""),
        privilege_types=[str(item) for item in obj.get("privilegeTypes", [])],
    )


def excluded_by_name(value: str) -> bool:
    lower = value.lower()
    return any(keyword.lower() in lower for keyword in DAC_EXCLUDED_NAME_KEYWORDS)


def privilege_requires_uhdc(privilege: DacPrivilege) -> bool:
    return "uhdc" in privilege.name.lower()


def connection_allowed_for_privilege(connection: DacConnection, privilege: DacPrivilege) -> bool:
    if not privilege_requires_uhdc(privilege):
        return True
    return "uhdc" in connection.name.lower()


def extract_endpoint_values(value) -> list[str]:
    """Connection detail에서 endpoint/IP/host 성격의 문자열을 모읍니다."""

    result: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_lower = str(key).lower()
            if isinstance(item, str) and any(token in key_lower for token in ("endpoint", "host", "ip", "address")):
                if item and item not in result:
                    result.append(item)
            for child in extract_endpoint_values(item):
                if child not in result:
                    result.append(child)
    elif isinstance(value, list):
        for item in value:
            for child in extract_endpoint_values(item):
                if child not in result:
                    result.append(child)
    return result


def looks_like_endpoint_keyword(keyword: str) -> bool:
    value = keyword.strip().lower()
    if not value:
        return False
    return "." in value or ":" in value or any(char.isdigit() for char in value)


def cluster_endpoint(cluster: dict) -> str:
    host = str(cluster.get("host") or cluster.get("cloudIdentifier") or "")
    port = str(cluster.get("port") or "")
    if host and port:
        return f"{host}:{port}"
    return host


def endpoint_label(connection: DacConnection) -> str:
    return ", ".join(connection.endpoints or []) or "-"


SQL_PRIVILEGE_DB_TYPES = {
    "MYSQL",
    "MARIADB",
    "POSTGRESQL",
    "REDSHIFT",
    "SQLSERVER",
    "AZURESQL",
    "ORACLE",
    "TIBERO",
    "HANA",
    "SNOWFLAKE",
    "SINGLESTORE",
    "VERTICA",
    "TERADATA",
    "CLICKHOUSE",
    "SHARDINGSPHERE_MYSQL",
}

PRIVILEGE_FAMILY_NAME_ALIASES = {
    "RDS": ("rds", "mysql", "mariadb", "postgres", "postgresql", "redshift", "oracle", "hana", "sqlserver", "tibero"),
    "REDIS": ("redis", "valkey", "elasticache"),
    "MONGODB": ("mongodb", "mongo", "documentdb", "document"),
}

PRIVILEGE_FAMILY_VENDOR_ALIASES = {
    "REDIS": ("redis", "valkey"),
    "MONGODB": ("mongodb", "mongo", "documentdb"),
}


def dac_privilege_family(connection: DacConnection) -> str:
    database_type = connection.database_type.upper()
    if database_type in SQL_PRIVILEGE_DB_TYPES:
        return "RDS"
    if database_type in ("MONGODB", "DOCUMENTDB"):
        return "MONGODB"
    return database_type or "UNKNOWN"


def privilege_family_rows(connections: list[DacConnection]) -> list[list[str]]:
    return [
        [dac_privilege_family(connection), connection.database_type, connection.name, endpoint_label(connection)]
        for connection in connections
    ]


def selected_privilege_families(connections: list[DacConnection]) -> list[str]:
    result: list[str] = []
    for connection in connections:
        family = dac_privilege_family(connection)
        if family not in result:
            result.append(family)
    return result


def privilege_matches_family(privilege: DacPrivilege, family: str) -> bool:
    name = privilege.name.lower()
    vendor = privilege.vendor.lower()
    name_aliases = PRIVILEGE_FAMILY_NAME_ALIASES.get(family, (family.lower(),))
    vendor_aliases = PRIVILEGE_FAMILY_VENDOR_ALIASES.get(family, ())
    return any(alias in name for alias in name_aliases) or any(alias == vendor for alias in vendor_aliases)


def dac_asset_database_type(asset: AssetIdentity) -> str:
    for tag in asset.tags or []:
        if normalize_key(tag.key) == "databasetype":
            return tag.value.upper()
    return ""


def dac_asset_is_grantable(asset: AssetIdentity) -> bool:
    if excluded_by_name(asset.name):
        return False
    database_type = dac_asset_database_type(asset)
    return database_type != "CUSTOM"


def sort_privileges(privileges: list[DacPrivilege]) -> list[DacPrivilege]:
    order = {"RW": 0, "RO": 1, "DBA": 2}
    return sorted(privileges, key=lambda item: (order.get(dac_permission_kind(item), 9), item.name))


def user_names(users: list[User]) -> str:
    return ", ".join(user.name for user in users) or "-"


def norm_text(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def endpoint_matches(csv_endpoints: list[str] | None, api_endpoints: list[str] | None) -> bool:
    csv_values = [norm_text(item) for item in (csv_endpoints or []) if item]
    api_values = [norm_text(item) for item in (api_endpoints or []) if item]
    if not csv_values or not api_values:
        return True
    for csv_value in csv_values:
        for api_value in api_values:
            if csv_value == api_value or csv_value in api_value or api_value in csv_value:
                return True
    return False


class DacConnectionRepository:
    def __init__(self, client):
        self.client = client
        self.local_reference = LocalAssetReference()
        self.detail_cache: dict[str, list[DacConnection]] = {}
        self.endpoint_cache: dict[str, list[str]] = {}
        self.full_scan_cache: list[DacConnection] | None = None
        self.search_cache: dict[str, list[DacConnection]] = {}

    def search_candidates(self, keyword: str) -> list[DacConnection]:
        """DB 후보를 grant 가능한 cluster 객체 기준으로 찾는다.

        `/dac/connections`의 uuid는 connection UUID이고, grant API에는
        detail 응답의 `common.clusters[].uuid`를 clusterUuid로 넣어야 합니다.
        """

        keyword = keyword.strip()
        cache_key = normalize_search_key(keyword)
        if not cache_key:
            print("[DAC SEARCH] 빈 검색어는 DB 조회를 실행하지 않습니다.")
            return []
        if cache_key in self.search_cache:
            print(f"[DAC CACHE] 검색 cache 사용: {keyword}")
            return list(self.search_cache[cache_key])
        if is_full_search(keyword):
            print("[DAC SEARCH] 전체 DB 검색 요청입니다. full scan cache를 사용합니다.")
            connections = self.full_scan_connections()
            self.search_cache[cache_key] = connections
            return list(connections)
        found: dict[str, DacConnection] = {}
        for connection in self.local_reference.search_dac_connections(keyword):
            found[connection.uuid] = connection
        if found:
            print(f"[LOCAL DAC] CSV 참조에서 후보 {len(found)}개를 찾았습니다.")
            connections = list(found.values())
            self.search_cache[cache_key] = connections
            return list(connections)
        for connection in self.expand_connection_groups(self.search_by_api_name(keyword)):
            found[connection.uuid] = connection
        if looks_like_endpoint_keyword(keyword) or not found:
            for connection in self.scan_by_keyword(keyword):
                found[connection.uuid] = connection
        connections = list(found.values())
        self.search_cache[cache_key] = connections
        return list(connections)

    def search_by_api_name(self, keyword: str) -> list[DacConnection]:
        if not keyword.strip() or is_full_search(keyword):
            return []
        data = self.client.request(
            "GET",
            f"/api/external/v2/dac/connections?pageNumber=0&pageSize={DAC_PAGE_SIZE}&connectionName={quote(keyword)}",
        )
        items = response_list(data)
        groups = self.filter_connection_groups(items)
        if items and not groups:
            print(f"  - {keyword}: 검색 결과는 있었지만 CUSTOM database, internal-only 또는 삭제 DB라 제외했습니다.")
        return groups

    def scan_by_keyword(self, keyword: str) -> list[DacConnection]:
        needle = keyword.lower()
        if not needle:
            return []
        found: dict[str, DacConnection] = {}
        for connection in self.full_scan_connections():
            fields = [connection.name]
            fields.extend(connection.endpoints or [])
            haystack = " ".join(fields).lower()
            if needle in haystack:
                found[connection.uuid] = connection
        return list(found.values())

    def full_scan_connections(self) -> list[DacConnection]:
        if self.full_scan_cache is not None:
            print(f"[DAC CACHE] 전체 scan cache {len(self.full_scan_cache)}개 사용")
            return self.full_scan_cache
        scanned: dict[str, DacConnection] = {}
        for page in page_numbers(MAX_DAC_CONNECTION_SCAN_PAGES):
            data = self.client.request(
                "GET",
                f"/api/external/v2/dac/connections?pageNumber={page}&pageSize={DAC_PAGE_SIZE}",
            )
            items = response_list(data)
            if not items:
                break
            for connection in self.expand_connection_groups(self.filter_connection_groups(items)):
                scanned[connection.uuid] = connection
            page_data = data.get("page", {}) if isinstance(data, dict) else {}
            total_pages = int(page_data.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < DAC_PAGE_SIZE:
                break
        else:
            warn_scan_limit("DAC connection scan", MAX_DAC_CONNECTION_SCAN_PAGES, DAC_PAGE_SIZE)
        self.full_scan_cache = list(scanned.values())
        return self.full_scan_cache

    def expand_connection_groups(self, groups: list[DacConnection]) -> list[DacConnection]:
        result: list[DacConnection] = []
        for group in groups:
            result.extend(self.connection_clusters(group))
        return result

    def connection_clusters(self, group: DacConnection) -> list[DacConnection]:
        if group.connection_uuid in self.detail_cache:
            return self.detail_cache[group.connection_uuid]
        local_clusters = self.local_reference.dac_connection_clusters(group.connection_uuid)
        if local_clusters:
            self.detail_cache[group.connection_uuid] = local_clusters
            return local_clusters
        try:
            data = self.client.request("GET", f"/api/external/v2/dac/connections/{group.connection_uuid}")
        except Exception:
            self.detail_cache[group.connection_uuid] = []
            return []

        common = data.get("common", data) if isinstance(data, dict) else {}
        name = first(common, "name") or group.name
        database_type = first(common, "databaseType") or group.database_type
        cloud_provider_type = first(common, "cloudProviderType") or group.cloud_provider_type
        connection_uuid = first(common, "uuid") or group.connection_uuid
        clusters = common.get("clusters", []) if isinstance(common, dict) else []
        result: list[DacConnection] = []
        for cluster in clusters or []:
            if not isinstance(cluster, dict) or cluster.get("deleted"):
                continue
            cluster_uuid = first(cluster, "uuid", "clusterUuid")
            if not cluster_uuid:
                continue
            endpoint = cluster_endpoint(cluster)
            connection = DacConnection(
                uuid=cluster_uuid,
                name=name,
                database_type=database_type,
                connection_uuid=connection_uuid,
                cloud_provider_type=cloud_provider_type,
                endpoints=[endpoint] if endpoint else [],
                cluster_type=first(cluster, "replicationType", "type"),
                deleted=False,
            )
            result.append(self.attach_cluster_endpoints(connection))
        self.detail_cache[group.connection_uuid] = result
        return result

    def connection_clusters_from_api(self, group_uuid: str) -> list[DacConnection]:
        """CSV를 건너뛰고 connection group 하나의 현재 API detail을 읽습니다."""

        if not group_uuid:
            return []
        try:
            data = self.client.request("GET", f"/api/external/v2/dac/connections/{group_uuid}")
        except Exception:
            return []
        common = data.get("common", data) if isinstance(data, dict) else {}
        name = first(common, "name")
        database_type = first(common, "databaseType")
        cloud_provider_type = first(common, "cloudProviderType")
        connection_uuid = first(common, "uuid") or group_uuid
        clusters = common.get("clusters", []) if isinstance(common, dict) else []
        result: list[DacConnection] = []
        for cluster in clusters or []:
            if not isinstance(cluster, dict) or cluster.get("deleted"):
                continue
            cluster_uuid = first(cluster, "uuid", "clusterUuid")
            if not cluster_uuid:
                continue
            endpoint = cluster_endpoint(cluster)
            result.append(
                DacConnection(
                    uuid=cluster_uuid,
                    name=name,
                    database_type=database_type,
                    connection_uuid=connection_uuid,
                    cloud_provider_type=cloud_provider_type,
                    endpoints=[endpoint] if endpoint else [],
                    cluster_type=first(cluster, "replicationType", "type"),
                    deleted=False,
                )
            )
        return result

    def attach_cluster_endpoints(self, connection: DacConnection) -> DacConnection:
        if connection.uuid not in self.endpoint_cache:
            endpoints: list[str] = []
            for endpoint in connection.endpoints or []:
                if endpoint and endpoint not in endpoints:
                    endpoints.append(endpoint)
            for path in (
                f"/api/external/v2/dac/connections/clusters/{connection.uuid}/instances",
            ):
                try:
                    data = self.client.request("GET", path)
                except Exception:
                    continue
                for endpoint in extract_endpoint_values(data):
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
            self.endpoint_cache[connection.uuid] = endpoints
        connection.endpoints = self.endpoint_cache[connection.uuid]
        return connection

    def filter_connection_groups(self, items: list[dict]) -> list[DacConnection]:
        result = []
        for item in items:
            connection = to_dac_connection(item)
            if not connection.uuid:
                continue
            if connection.deleted:
                continue
            if connection.database_type.upper() == "CUSTOM":
                continue
            if excluded_by_name(connection.name):
                continue
            result.append(connection)
        return result


class DacPrivilegeRepository:
    def __init__(self, client):
        self.client = client
        self.all_cache: list[DacPrivilege] | None = None

    def list_all(self) -> list[DacPrivilege]:
        if self.all_cache is not None:
            print(f"[DAC PRIVILEGE CACHE] privilege {len(self.all_cache)}개 사용")
            return list(self.all_cache)
        privileges: dict[str, DacPrivilege] = {}
        for page in page_numbers(MAX_DAC_CONNECTION_SCAN_PAGES):
            data = self.client.request("GET", f"/api/external/v2/privileges?pageNumber={page}&pageSize={DAC_PAGE_SIZE}")
            items = response_list(data)
            if not items:
                break
            for item in items:
                privilege = to_dac_privilege(item)
                if privilege.uuid and privilege.status.upper() == "ACTIVE":
                    privileges[privilege.uuid] = privilege
            page_data = data.get("page", {}) if isinstance(data, dict) else {}
            total_pages = int(page_data.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < DAC_PAGE_SIZE:
                break
        else:
            warn_scan_limit("DAC privilege scan", MAX_DAC_CONNECTION_SCAN_PAGES, DAC_PAGE_SIZE)
        self.all_cache = list(privileges.values())
        return list(self.all_cache)

    def search(self, keyword: str) -> list[DacPrivilege]:
        if not keyword.strip():
            return []
        if is_full_search(keyword):
            return self.list_all()
        needle = keyword.lower()
        return [
            privilege
            for privilege in self.list_all()
            if needle in privilege.name.lower() or needle in privilege.vendor.lower()
        ]


class DacTool:
    """DB connection 객체 기준으로 DAC DB 권한을 부여/회수합니다."""

    def __init__(self, client, runtime, resolver: Resolver, tag_lookup_tool=None):
        self.client = client
        self.runtime = runtime
        self.resolver = resolver
        self.tag_lookup_tool = tag_lookup_tool
        self.connections = DacConnectionRepository(client)
        self.privileges = DacPrivilegeRepository(client)
        self.report = ReportWriter(runtime)

    def precheck_connections_against_csv(self, connections: list[DacConnection]) -> bool:
        """선택한 로컬 CSV DB 대상이 현재 API detail과 같은지 비교합니다."""

        rows: list[list[str]] = []
        failed = False
        api_cache: dict[str, list[DacConnection]] = {}
        for connection in connections:
            csv_connection = self.connections.local_reference.dac_connection_reference(connection)
            if not csv_connection:
                continue
            group_uuid = csv_connection.connection_uuid or connection.connection_uuid
            if group_uuid not in api_cache:
                api_cache[group_uuid] = self.connections.connection_clusters_from_api(group_uuid)
            api_connection = next((item for item in api_cache[group_uuid] if item.uuid == csv_connection.uuid), None)
            notes: list[str] = []
            ok = api_connection is not None
            if not api_connection:
                notes.append("API detail에 clusterUuid 없음")
            else:
                if norm_text(csv_connection.name) and norm_text(api_connection.name) != norm_text(csv_connection.name):
                    ok = False
                    notes.append("DB명 불일치")
                if norm_text(csv_connection.database_type) and norm_text(api_connection.database_type) != norm_text(csv_connection.database_type):
                    ok = False
                    notes.append("DB type 불일치")
                if not endpoint_matches(csv_connection.endpoints, api_connection.endpoints):
                    ok = False
                    notes.append("endpoint 불일치")
            if not ok:
                failed = True
            rows.append([
                "OK" if ok else "FAIL",
                csv_connection.name,
                csv_connection.database_type,
                csv_connection.uuid,
                " / ".join(notes) or "-",
            ])
        if rows:
            print("\nDAC CSV/API 사전 검증")
            ConsoleView.auto_table(
                ["검증", "DB", "type", "clusterUuid", "비고"],
                rows,
                [6, 24, 10, 36, 24],
                [6, 46, 14, 38, 48],
            )
        return not failed

    def run(self, action: str = "grant"):
        try:
            action = action.lower() or "grant"
            if action == "revoke":
                self.run_revoke()
                return

            state = run_input_steps([
                self.step_select_grant_connections,
                self.step_select_grant_privilege,
                self.step_read_grant_expiry,
                self.step_select_grant_users,
                self.step_confirm_grant_plan,
            ])
            if not state.get("confirmed"):
                print("실행하지 않았습니다.")
                return
            connections: list[DacConnection] = state["connections"]
            privilege: DacPrivilege = state["privilege"]
            expiry: str = state["expiry"]
            users: list[User] = state["users"]
            if not users or not connections:
                print("실행 대상이 없습니다.")
                return
            if not self.precheck_connections_against_csv(connections):
                print("[PRECHECK_FAIL] CSV와 API DB 정보가 달라서 DAC 권한 변경을 중단합니다.")
                return
            verified: dict[str, list[DacConnection]] = {}
            body = {
                "force": True,
                "grants": [
                    {
                        "clusterUuid": connection.uuid,
                        "privilegeUuid": privilege.uuid,
                        "expiryAt": dac_expiry_at(expiry),
                    }
                    for connection in connections
                ],
            }
            for user in users:
                self.client.request("POST", f"/api/external/v2/dac/access-controls/{user.uuid}/bulk-grant", body)
                verified[user.uuid] = self.verify_user(user, privilege, connections)
            self.print_result(users, privilege, connections, verified)
            done_users = [user for user in users if len(verified.get(user.uuid, [])) == len(connections)]
            if done_users:
                context = read_report_context()
                path = self.report.append_dac_grants(context, privilege, expiry, done_users, connections)
                ConsoleView.table(["CSV 기록"], [[path]], [80])
        except Back:
            print("이전 단계로 돌아갑니다.")

    def run_revoke(self):
        state = run_input_steps([
            self.step_select_revoke_users,
            self.step_select_revoke_permissions,
            self.step_confirm_revoke_plan,
        ])
        if not state.get("confirmed"):
            print("실행하지 않았습니다.")
            return
        selected_by_user: dict[str, list[DacAssignedPermission]] = state["selected_by_user"]
        verified: dict[str, list[DacConnection]] = {}
        users: list[User] = state["users"]
        for user in users:
            permissions = selected_by_user.get(user.uuid, [])
            if not permissions:
                continue
            connections = [permission.connection for permission in permissions]
            body = {"clusterUuids": [connection.uuid for connection in connections]}
            self.client.request("POST", f"/api/external/v2/dac/access-controls/{user.uuid}/revoke", body)
            verified[user.uuid] = self.verify_user_revoke(user, connections)
        self.print_revoke_result(users, selected_by_user, verified)

    def step_select_grant_connections(self, state: dict):
        connections = self.select_connections()
        if not connections:
            print("선택한 DB가 없습니다.")
            raise Back
        state["connections"] = connections

    def step_select_grant_privilege(self, state: dict):
        connections = state["connections"]
        family = self.require_single_privilege_family(connections)
        if not family:
            raise Back
        privilege = self.select_privilege(connections, family)
        filtered = self.filter_selected_connections_for_privilege(connections, privilege)
        if not filtered:
            print("선택한 privilege에 맞는 DB가 없습니다.")
            raise Back
        state["privilege"] = privilege
        state["connections"] = filtered

    def step_read_grant_expiry(self, state: dict):
        privilege = state["privilege"]
        state["expiry"] = read_defaulted(
            f"만료일 YYYY-MM-DD [{default_dac_expiry(privilege)} | {dac_permission_kind(privilege)} 기본]",
            default_dac_expiry(privilege),
        )

    def step_select_grant_users(self, state: dict):
        state["users"] = self.select_users("DAC 권한 부여 대상 사용자를 입력하세요.")

    def step_confirm_grant_plan(self, state: dict):
        connections = state["connections"]
        privilege = state["privilege"]
        users = state["users"]
        expiry = state["expiry"]
        if not users or not connections:
            state["confirmed"] = False
            return
        self.print_plan(privilege, connections, users, expiry)
        if not self.confirm_partner_dba(privilege, users):
            print("중단했습니다.")
            state["confirmed"] = False
            return
        state["confirmed"] = self.confirm("DAC 권한 부여")

    def step_select_revoke_users(self, state: dict):
        state["users"] = self.select_users("DAC 권한 회수 대상 사용자를 입력하세요.")

    def step_select_revoke_permissions(self, state: dict):
        users = state["users"]
        assigned: list[DacAssignedPermission] = []
        for user in users:
            permissions = self.user_assigned_permissions(user)
            if not permissions:
                print(f"  - {user.name}: 회수 가능한 DAC 권한 없음")
                continue
            assigned.extend(permissions)
        selected = self.choose_revoke_permissions(assigned)
        selected_by_user: dict[str, list[DacAssignedPermission]] = {}
        for permission in selected:
            selected_by_user.setdefault(permission.user.uuid, []).append(permission)
        state["selected_by_user"] = selected_by_user

    def step_confirm_revoke_plan(self, state: dict):
        users = state["users"]
        selected_by_user = state["selected_by_user"]
        if not any(selected_by_user.values()):
            state["confirmed"] = False
            return
        self.print_revoke_plan(users, selected_by_user)
        state["confirmed"] = self.confirm_revoke("DAC 권한 회수")

    def require_single_privilege_family(self, connections: list[DacConnection]) -> str:
        families = selected_privilege_families(connections)
        if len(families) == 1:
            return families[0]
        print("\n[DAC_TYPE_MIXED] 한 번에 같은 privilege를 적용할 수 없는 DB 타입이 섞여 있습니다.")
        ConsoleView.auto_table(
            ["권한군", "DB type", "DB", "endpoint/IP"],
            privilege_family_rows(connections),
            [8, 10, 24, 28],
            [12, 14, 42, 62],
        )
        print("RDS/Redis/MongoDB처럼 권한군이 다르면 나눠서 실행하세요.")
        return ""

    def select_privilege(self, connections: list[DacConnection], family: str) -> DacPrivilege:
        candidates = self.privilege_candidates_for_family(family)
        if candidates:
            return self.choose_privilege(family, candidates)
        print(f"[DAC_PRIVILEGE_NOT_FOUND] {family} 권한 후보를 자동으로 찾지 못했습니다.")
        while True:
            keyword = read_value("추가 privilege 검색어: ")
            candidates = [
                privilege
                for privilege in self.privileges.search(keyword)
                if privilege_matches_family(privilege, family)
            ]
            if not candidates:
                print(f"[DAC_PRIVILEGE_NOT_FOUND] {keyword}")
                continue
            return self.choose_privilege(family, candidates)

    def privilege_candidates_for_family(self, family: str) -> list[DacPrivilege]:
        return sort_privileges([
            privilege
            for privilege in self.privileges.list_all()
            if privilege_matches_family(privilege, family)
        ])

    def choose_privilege(self, family: str, candidates: list[DacPrivilege]) -> DacPrivilege:
        current = sort_privileges(candidates)
        while True:
            print(f"\nDAC privilege 후보: {family}")
            rows = [
                [str(idx), item.name, dac_permission_kind(item), item.vendor, ",".join(item.privilege_types[:6])]
                for idx, item in enumerate(current, 1)
            ]
            ConsoleView.auto_table(
                ["번호", "privilege", "권한", "vendor", "types"],
                rows,
                [4, 18, 6, 8, 24],
                [4, 28, 8, 12, 58],
            )
            selected = read_value("권한 번호 선택 또는 추가 검색어: ")
            if selected.isdigit() and 1 <= int(selected) <= len(current):
                return current[int(selected) - 1]
            narrowed = [
                item
                for item in current
                if selected.lower() in item.name.lower() or selected.lower() in dac_permission_kind(item).lower()
            ]
            if narrowed:
                current = narrowed
                continue
            print("잘못된 번호이거나 후보를 좁히지 못했습니다.")

    def select_connections(self) -> list[DacConnection]:
        while True:
            mode = read_value("DB 선택 방식 [search/s=이름/IP검색, tag/t=태그검색, 기본 search]: ", allow_empty=True).lower()
            if mode in ("tag", "t", "태그"):
                connections = self.select_connections_by_tag()
                if connections:
                    self.print_selected_connections(connections)
                    return connections
                print("[DAC_TAG_NOT_FOUND] 태그로 grant 가능한 DB cluster를 찾지 못했습니다. 선택 방식으로 돌아갑니다.")
                continue
            if mode in ("", "search", "s", "검색", "이름", "ip"):
                break
            print("DB 선택 방식은 search 또는 tag 중 하나를 입력하세요.")

        print("\nDB connection 이름, endpoint 또는 IP를 입력하세요.")
        ConsoleView.table(
            ["입력", "처리"],
            [
                ["DB명", "부분 검색 후 후보가 여러 개면 번호 선택"],
                ["endpoint/IP", "기본으로 검색하며 같은 IP가 여러 DB에 매칭되면 후보 선택"],
                ["여러 개", "쉼표로 입력하거나 후보 표에서 1,2 또는 a 선택"],
                ["자동 제외", "CUSTOM database, internal-only 포함 DB"],
            ],
            [12, 70],
        )
        while True:
            raw = read_role_keyword("DB 검색값(쉼표로 여러 개 가능, Tab=미리보기): ", self.preview_connections)
            selected: dict[str, DacConnection] = {}
            try:
                for keyword in read_csv_items(raw):
                    for connection in self.resolve_connection_keyword(keyword):
                        selected[connection.uuid] = connection
            except Back:
                continue
            if selected:
                connections = list(selected.values())
                self.print_selected_connections(connections)
                return connections
            print("선택된 DB가 없습니다. 검색값을 다시 입력하세요.")

    def select_connections_by_tag(self) -> list[DacConnection]:
        if not self.tag_lookup_tool:
            print("[TAG_UNAVAILABLE] 태그 검색 도구가 연결되어 있지 않습니다.")
            return []
        assets = self.tag_lookup_tool.select_assets_by_tag(
            "dac",
            "DAC DB 태그검색",
            asset_filter=dac_asset_is_grantable,
            filter_message="grant 대상이 아닌 CUSTOM database/internal-only 후보",
        )
        selected: dict[str, DacConnection] = {}
        for asset in assets:
            if not asset.uuid:
                print(f"  - {asset.name}: connection UUID 없음")
                continue
            if excluded_by_name(asset.name):
                print(f"  - {asset.name}: internal-only 제외")
                continue
            group = DacConnection(
                uuid=asset.uuid,
                name=asset.name,
                database_type="",
                connection_uuid=asset.uuid,
                cloud_provider_type=asset.csp,
            )
            for connection in self.connections.connection_clusters(group):
                if connection.database_type.upper() == "CUSTOM":
                    print(f"  - {connection.name}: CUSTOM database 제외")
                    continue
                if excluded_by_name(connection.name):
                    print(f"  - {connection.name}: internal-only 제외")
                    continue
                selected[connection.uuid] = connection
        return list(selected.values())

    def preview_connections(self, raw: str):
        keywords = read_csv_items(raw)
        if not keywords:
            print("[DAC PREVIEW] 검색어를 입력한 뒤 Tab을 누르세요.")
            return
        rows = []
        for keyword in keywords:
            candidates = self.connections.search_candidates(keyword)[:DAC_CANDIDATE_DISPLAY_LIMIT]
            if not candidates:
                rows.append([keyword, "-", "-", "-", "후보 없음"])
                continue
            for item in candidates[:10]:
                rows.append([
                    keyword,
                    item.name,
                    item.database_type,
                    endpoint_label(item),
                    item.cluster_type or "-",
                ])
        ConsoleView.auto_table(
            ["검색어", "DB", "type", "endpoint/IP", "cluster"],
            rows,
            [10, 24, 8, 28, 8],
            [16, 46, 14, 76, 12],
        )
        print("[DAC PREVIEW] 위 표는 미리보기입니다. 선택하려면 같은 검색어에서 Enter를 누르세요.")

    def resolve_connection_keyword(self, keyword: str) -> list[DacConnection]:
        candidates = self.connections.search_candidates(keyword)
        if not candidates:
            print(f"  - {keyword}: DB_NOT_FOUND_OR_EXCLUDED")
            return []
        if len(candidates) == 1:
            connection = candidates[0]
            ConsoleView.auto_table(
                ["선택", "DB", "type", "endpoint/IP", "cluster"],
                [[
                    "대상",
                    connection.name,
                    connection.database_type,
                    endpoint_label(connection),
                    connection.cluster_type or "-",
                ]],
                [6, 24, 8, 28, 8],
                [6, 46, 14, 76, 12],
            )
            return candidates
        return self.choose_connections(keyword, candidates)

    def choose_connections(self, keyword: str, candidates: list[DacConnection]) -> list[DacConnection]:
        shown = candidates[:DAC_CANDIDATE_DISPLAY_LIMIT]
        print(f"\n  {keyword}: DB 후보 {len(candidates)}개")
        rows = [
            [str(idx), item.name, item.database_type, endpoint_label(item), item.cluster_type or "-"]
            for idx, item in enumerate(shown, 1)
        ]
        ConsoleView.auto_table(
            ["번호", "DB", "type", "endpoint/IP", "cluster"],
            rows,
            [4, 24, 8, 28, 8],
            [4, 46, 14, 76, 12],
        )
        if len(candidates) > len(shown):
            print(f"  {len(candidates) - len(shown)}개 더 있음. 검색어를 더 좁히세요.")
        while True:
            value = read_value("    선택 번호(1 / 1,2 / a=표시된 전체 / s=건너뛰기): ")
            if value.lower() in ("s", "skip", "건너뛰기"):
                return []
            numbers = parse_number_selection(value, len(shown))
            if numbers:
                return [shown[number - 1] for number in numbers]
            print("    잘못된 번호입니다.")

    def filter_selected_connections_for_privilege(
        self,
        connections: list[DacConnection],
        privilege: DacPrivilege,
    ) -> list[DacConnection]:
        if not privilege_requires_uhdc(privilege):
            return connections
        allowed = [connection for connection in connections if connection_allowed_for_privilege(connection, privilege)]
        excluded = [connection for connection in connections if connection not in allowed]
        if excluded:
            print("\n[DAC_FILTER] UHDC privilege는 DB 이름에 uhdc가 포함된 객체만 유지합니다.")
            self.print_connection_table("제외 DB", excluded)
        return allowed

    @staticmethod
    def print_selected_connections(connections: list[DacConnection]):
        DacTool.print_connection_table("선택 DB", connections)

    @staticmethod
    def print_connection_table(title: str, connections: list[DacConnection]):
        print(f"\n{title}")
        ConsoleView.auto_table(
            ["DB", "type", "endpoint/IP", "cluster"],
            [[item.name, item.database_type, endpoint_label(item), item.cluster_type or "-"] for item in connections],
            [24, 8, 28, 8],
            [46, 14, 76, 12],
        )

    def select_users(self, title: str = "DAC 권한 대상 사용자를 입력하세요.") -> list[User]:
        while True:
            print(f"\n{title}")
            values = []
            while True:
                raw = read_value("> ", allow_empty=True)
                if not raw:
                    break
                values.extend(read_csv_items(raw))
            if not values:
                return []
            selected: dict[str, User] = {}
            unresolved: list[str] = []
            for keyword in values:
                if excluded_by_name(keyword):
                    print(f"  - {keyword}: internal-only 제외")
                    continue
                users, missing = self.resolver.resolve_user_inputs([keyword])
                unresolved.extend(missing)
                for user in users:
                    haystack = " ".join([user.name, user.login_id, user.email])
                    if excluded_by_name(haystack):
                        print(f"  - {user.name}: internal-only 사용자 제외")
                        continue
                    selected[user.uuid] = user
            if unresolved:
                print("[USER_INPUT_RETRY] 찾지 못한 사용자가 있어 사용자 입력 단계로 돌아갑니다.")
                ConsoleView.table(["NOT_FOUND"], [[item] for item in unresolved], [40])
                continue
            return list(selected.values())

    def user_assigned_permissions(self, user: User) -> list[DacAssignedPermission]:
        data = self.client.request("GET", f"/api/external/v2/dac/access-controls/{user.uuid}")
        mapped = response_list({"list": data.get("mappedConnections", [])}) if isinstance(data, dict) else []
        permissions: list[DacAssignedPermission] = []
        for item in mapped:
            status = str(item.get("status") or "").upper()
            if status and status != "ACTIVE":
                continue
            privilege_obj = item.get("privilege", {}) if isinstance(item.get("privilege"), dict) else {}
            privilege = DacPrivilege(
                uuid=first(privilege_obj, "uuid", "privilegeUuid"),
                name=first(privilege_obj, "name", "privilegeName") or first(item, "privilegeName"),
                vendor=first(privilege_obj, "privilegeVendor", "vendor"),
                status=status or "ACTIVE",
                privilege_types=[],
            )
            cluster_uuid = first(item, "clusterUuid", "uuid")
            if not cluster_uuid:
                continue
            connection = DacConnection(
                uuid=cluster_uuid,
                name=first(item, "connectionName", "name", "clusterName", "databaseName") or "-",
                database_type=first(item, "databaseType", "dbType"),
                connection_uuid=first(item, "connectionUuid", "connectionGroupUuid"),
                cloud_provider_type=first(item, "cloudProviderType"),
                endpoints=extract_endpoint_values(item),
                cluster_type=first(item, "clusterType", "replicationType", "type"),
            )
            permissions.append(DacAssignedPermission(user, connection, privilege, status or "ACTIVE"))
        return permissions

    def choose_revoke_permissions(
        self,
        permissions: list[DacAssignedPermission],
    ) -> list[DacAssignedPermission]:
        if not permissions:
            return []
        current = permissions
        while True:
            rows = [
                [
                    str(idx),
                    item.user.name,
                    item.connection.name,
                    item.connection.database_type or "-",
                    item.privilege.name or "-",
                    endpoint_label(item.connection),
                ]
                for idx, item in enumerate(current, 1)
            ]
            print("\n[DAC REVOKE] 현재 부여된 DB 권한 중 회수 대상을 선택하세요.")
            ConsoleView.auto_table(
                ["번호", "사용자", "DB", "type", "privilege", "endpoint/IP"],
                rows,
                [4, 12, 24, 8, 14, 24],
                [4, 24, 52, 14, 24, 76],
            )
            value = read_value("회수 번호(1 / 1,2 / a=전체) 또는 검색어, /b=사용자 다시 입력: ")
            numbers = parse_number_selection(value, len(current))
            if numbers:
                return [current[number - 1] for number in numbers]
            if value.strip().isdigit():
                print("잘못된 번호입니다.")
                continue
            needle = value.lower()
            narrowed = [
                item
                for item in current
                if needle in " ".join([
                    item.user.name,
                    item.connection.name,
                    item.connection.database_type,
                    item.privilege.name,
                    endpoint_label(item.connection),
                ]).lower()
            ]
            if not narrowed:
                print(f"[DAC_REVOKE_REFINE_NOT_FOUND] {value}")
                continue
            current = narrowed

    @staticmethod
    def print_plan(privilege: DacPrivilege, connections: list[DacConnection], users: list[User], expiry: str):
        print("\n[OPERATION] DAC 권한 부여")
        ConsoleView.auto_table(
            ["항목", "값"],
            [
                ["작업", "DAC 권한 부여"],
                ["privilege", f"{privilege.name} ({privilege.vendor})"],
                ["권한", dac_permission_kind(privilege)],
                ["DB 수", f"{len(connections)}개"],
                ["사용자", user_names(users)],
                ["만료일", expiry],
            ],
            [10, 24],
            [12, 90],
        )
        ConsoleView.auto_table(
            ["DB", "type", "endpoint/IP", "cluster"],
            [[item.name, item.database_type, endpoint_label(item), item.cluster_type or "-"] for item in connections],
            [24, 8, 28, 8],
            [46, 14, 76, 12],
        )
        ConsoleView.users("DAC 대상 사용자", users)

    @staticmethod
    def print_revoke_plan(users: list[User], selected_by_user: dict[str, list[DacAssignedPermission]]):
        selected = [item for items in selected_by_user.values() for item in items]
        print("\n[OPERATION] DAC 권한 회수")
        ConsoleView.auto_table(
            ["항목", "값"],
            [["작업", "DAC 권한 회수"], ["회수 권한", f"{len(selected)}건"], ["사용자", user_names(users)]],
            [10, 24],
            [12, 90],
        )
        ConsoleView.auto_table(
            ["사용자", "DB", "type", "privilege", "endpoint/IP"],
            [
                [
                    item.user.name,
                    item.connection.name,
                    item.connection.database_type or "-",
                    item.privilege.name or "-",
                    endpoint_label(item.connection),
                ]
                for item in selected
            ],
            [12, 24, 8, 14, 28],
            [24, 52, 14, 24, 76],
        )

    def confirm_partner_dba(self, privilege: DacPrivilege, users: list[User]) -> bool:
        danger = [user for user in users if user.domain_type == "partner" and dac_permission_kind(privilege) == "DBA"]
        if not danger:
            return True
        ConsoleView.users("협력사 DBA 권한 대상", danger)
        return read_value("협력사 사용자에게 DBA 권한을 부여하려면 CONFIRM-DAC-DBA 입력: ") == "CONFIRM-DAC-DBA"

    @staticmethod
    def confirm(operation: str = "DAC 권한 부여") -> bool:
        while True:
            value = read_value(f"\n{operation}를 실행할까요? [y/N, /b=이전 단계]: ", allow_empty=True).lower()
            if value in ("y", "yes"):
                return True
            if value in ("", "n", "no"):
                return False
            print("y 또는 n을 입력하세요.")

    @staticmethod
    def confirm_revoke(operation: str = "DAC 권한 회수") -> bool:
        while True:
            value = read_value(f"\n{operation}를 실행할까요? [y/N, /b=이전 단계]: ", allow_empty=True).lower()
            if value in ("y", "yes"):
                return True
            if value in ("", "n", "no"):
                return False
            print("y 또는 n을 입력하세요.")

    def verify_user(
        self,
        user: User,
        privilege: DacPrivilege,
        connections: list[DacConnection],
    ) -> list[DacConnection]:
        data = self.client.request("GET", f"/api/external/v2/dac/access-controls/{user.uuid}")
        mapped = response_list({"list": data.get("mappedConnections", [])}) if isinstance(data, dict) else []
        expected = {connection.uuid: connection for connection in connections}
        verified = []
        for item in mapped:
            cluster_uuid = str(item.get("clusterUuid") or "")
            privilege_obj = item.get("privilege", {}) if isinstance(item.get("privilege"), dict) else {}
            privilege_uuid = str(privilege_obj.get("uuid") or "")
            status = str(item.get("status") or "").upper()
            if cluster_uuid in expected and privilege_uuid == privilege.uuid and status == "ACTIVE":
                verified.append(expected[cluster_uuid])
        return verified

    def verify_user_revoke(self, user: User, connections: list[DacConnection]) -> list[DacConnection]:
        data = self.client.request("GET", f"/api/external/v2/dac/access-controls/{user.uuid}")
        mapped = response_list({"list": data.get("mappedConnections", [])}) if isinstance(data, dict) else []
        active_cluster_uuids = {
            str(item.get("clusterUuid") or "")
            for item in mapped
            if str(item.get("status") or "").upper() == "ACTIVE"
        }
        return [connection for connection in connections if connection.uuid not in active_cluster_uuids]

    @staticmethod
    def print_result(
        users: list[User],
        privilege: DacPrivilege,
        connections: list[DacConnection],
        verified: dict[str, list[DacConnection]],
    ):
        rows = []
        for user in users:
            done = verified.get(user.uuid, [])
            rows.append([user.name, privilege.name, f"{len(done)}/{len(connections)}"])
        ConsoleView.auto_table(["사용자", "privilege", "검증"], rows, [12, 18, 6], [24, 32, 8])

    @staticmethod
    def print_revoke_result(
        users: list[User],
        selected_by_user: dict[str, list[DacAssignedPermission]],
        verified: dict[str, list[DacConnection]],
    ):
        rows = []
        for user in users:
            permissions = selected_by_user.get(user.uuid, [])
            done = verified.get(user.uuid, [])
            rows.append([user.name, f"{len(done)}/{len(permissions)}"])
        ConsoleView.auto_table(["사용자", "회수 검증"], rows, [12, 8], [24, 10])
