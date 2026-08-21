from __future__ import annotations

import re

from .config import KAC_CANDIDATE_DISPLAY_LIMIT, KAC_DEFAULT_EXPIRY_DAYS, RuntimeConfig
from .io_utils import read_defaulted, read_role_keyword, read_user_inputs, read_value, run_input_steps
from .models import Back, KacRole, RolePlanEntry, User
from .report import ReportWriter, read_report_context
from .resolver import Resolver
from .api_utils import end_of_day_utc, inclusive_expiry_date, is_full_search, parse_number_selection, response_list
from .asset_tags import suggested_search_terms
from .asset_reference import LocalAssetReference
from .view import ConsoleView


def default_kac_expiry() -> str:
    return inclusive_expiry_date(KAC_DEFAULT_EXPIRY_DAYS)


def kac_expiration_date(expiry: str) -> str:
    # OpenAPI는 UTC ISO 8601 date-time을 요구합니다.
    return end_of_day_utc(expiry)


def to_kac_role(obj: dict) -> KacRole:
    policies = []
    for policy in obj.get("assignedPolicies", []) or []:
        if isinstance(policy, dict) and policy.get("name"):
            policies.append(str(policy["name"]))
    return KacRole(
        uuid=str(obj.get("uuid") or obj.get("roleUuid") or ""),
        name=str(obj.get("name") or obj.get("roleName") or ""),
        description=str(obj.get("description") or obj.get("roleDescription") or ""),
        policies=policies,
    )


def role_search_text(role: KacRole) -> str:
    return " ".join([role.name, role.description, " ".join(role.policies or [])]).lower()


def kac_description_value(description: str, key: str) -> str:
    pattern = rf"{key}s?\s*:\s*([^,|]+)"
    match = re.search(pattern, description or "", re.IGNORECASE)
    return match.group(1).strip() if match else ""


def kac_role_kind(role: KacRole) -> str:
    text = " ".join([role.name, role.description]).lower()
    if "admin" in text:
        return "ADMIN"
    if "viewer" in text or "view" in text:
        return "VIEWER"
    return "-"


def kac_role_parts(role: KacRole) -> dict[str, str]:
    name_parts = role.name.split("_")
    return {
        "kind": kac_role_kind(role),
        "csp": kac_description_value(role.description, "CSP") or (name_parts[0] if name_parts else ""),
        "account": kac_description_value(role.description, "Account") or (name_parts[1] if len(name_parts) > 1 else ""),
        "cluster": kac_description_value(role.description, "Cluster"),
        "namespace": kac_description_value(role.description, "Namespace"),
    }


class KacRoleRepository:
    """KAC role 후보를 CSV 먼저, 없으면 API cache 순서로 읽습니다."""

    def __init__(self, client):
        self.client = client
        self.local_reference = LocalAssetReference()
        self.roles: list[KacRole] | None = None

    def list_all(self) -> list[KacRole]:
        """API KAC role 목록을 반환하고 실행 중 메모리에 보관합니다."""

        if self.roles is None:
            data = self.client.request("GET", "/api/external/v2/kac/access-controls/roles")
            self.roles = [role for role in (to_kac_role(item) for item in response_list(data)) if role.uuid]
            print(f"[KAC CACHE] API role {len(self.roles)}개를 메모리에 올렸습니다.")
        return self.roles

    def list_all_api(self) -> list[KacRole]:
        data = self.client.request("GET", "/api/external/v2/kac/access-controls/roles")
        return [role for role in (to_kac_role(item) for item in response_list(data)) if role.uuid]

    def search_candidates(self, keyword: str) -> list[KacRole]:
        """로컬 CSV를 먼저 검색하고 없으면 API cache에서 찾습니다."""

        if is_full_search(keyword):
            return self.list_all()
        terms = [item for item in keyword.lower().split() if item]
        if not terms:
            print("[KAC SEARCH] 빈 검색어는 role 조회를 실행하지 않습니다.")
            return []
        local_roles = [
            role
            for role in self.local_reference.search_kac_roles(keyword)
            if all(term in role_search_text(role) for term in terms)
        ]
        if local_roles:
            print(f"[LOCAL KAC] role CSV에서 후보 {len(local_roles)}개를 찾았습니다.")
            return local_roles
        return [role for role in self.list_all() if all(term in role_search_text(role) for term in terms)]


class KacTool:
    """KAC Kubernetes role grant/revoke 업무 흐름을 담당한다."""

    def __init__(self, client, runtime: RuntimeConfig, resolver: Resolver, tag_lookup_tool=None):
        self.client = client
        self.runtime = runtime
        self.resolver = resolver
        self.tag_lookup_tool = tag_lookup_tool
        self.roles = KacRoleRepository(client)
        self.report = ReportWriter(runtime)
        self.user_role_cache: dict[str, list[KacRole]] = {}

    def run(self, action: str = ""):
        try:
            action = action or self.select_action()
            state = {"action": action}
            if action == "revoke":
                steps = [
                    self.step_select_roles_or_revoke_targets,
                    self.step_confirm_plan,
                ]
            else:
                steps = [
                    self.step_select_roles_or_revoke_targets,
                    self.step_read_grant_expiry,
                    self.step_build_grant_targets,
                    self.step_confirm_plan,
                ]
            state = run_input_steps(steps, state)
            action = state["action"]
            roles: list[KacRole] = state["roles"]
            expiry: str = state.get("expiry", "")
            targets_by_role: dict[str, list[User]] = state["targets_by_role"]
            entries: list[RolePlanEntry] = state["entries"]
            if not state.get("confirmed"):
                print("실행하지 않았습니다.")
                return
            if not self.precheck_roles_against_csv(roles):
                print("[PRECHECK_FAIL] CSV와 API KAC role 정보가 달라서 KAC role 변경을 중단합니다.")
                return
            verified_by_role = self.execute(action, roles, expiry, targets_by_role)
            self.print_result(action, roles, entries, verified_by_role)
            if action == "grant" and any(verified_by_role.values()):
                context = read_report_context()
                path = ""
                for role in roles:
                    users = verified_by_role.get(role.uuid, [])
                    if users:
                        path = self.report.append_kac_grants(context, role, expiry, users)
                ConsoleView.table(["CSV 기록"], [[path]], [80])
        except Back:
            print("이전 단계로 돌아갑니다.")

    def step_select_roles_or_revoke_targets(self, state: dict):
        if state["action"] == "revoke":
            users = self.read_target_users("KAC role 회수 대상 사용자를 입력하세요.")
            roles, targets_by_role, entries = self.build_revoke_targets_from_assigned(users)
            state["roles"] = roles
            state["targets_by_role"] = targets_by_role
            state["entries"] = entries
            return
        state["roles"] = self.select_roles()

    def step_read_grant_expiry(self, state: dict):
        if state["action"] == "grant":
            state["expiry"] = read_defaulted(f"만료일 YYYY-MM-DD [{default_kac_expiry()} | KAC 기본 1년]", default_kac_expiry())
        else:
            state["expiry"] = ""

    def step_build_grant_targets(self, state: dict):
        if state["action"] == "grant":
            targets_by_role, entries = self.build_grant_targets(state["roles"])
            state["targets_by_role"] = targets_by_role
            state["entries"] = entries

    def step_confirm_plan(self, state: dict):
        if not any(state["targets_by_role"].values()):
            print("실행 대상이 없습니다.")
            state["confirmed"] = False
            return
        self.print_plan(state["action"], state["roles"], state["entries"], state["expiry"])
        state["confirmed"] = self.confirm(state["action"])

    @staticmethod
    def select_action() -> str:
        while True:
            value = read_value("KAC 작업 [grant/revoke, 기본 grant]: ", allow_empty=True).lower()
            if value in ("", "grant", "g", "부여"):
                return "grant"
            if value in ("revoke", "r", "회수"):
                return "revoke"
            print("grant 또는 revoke를 입력하세요.")

    def select_roles(self) -> list[KacRole]:
        mode = read_value("KAC role 선택 방식 [search/s=role검색, tag/t=cluster태그검색, 기본 search]: ", allow_empty=True).lower()
        if mode in ("tag", "t", "태그"):
            roles = self.select_roles_by_tag()
            if roles:
                return roles
            print("[KAC_TAG_NOT_FOUND] 태그로 role 후보를 찾지 못했습니다. role 검색으로 전환합니다.")
        while True:
            keyword = read_role_keyword("KAC role 검색값(role명 / policy명, Tab=미리보기): ", self.preview_roles)
            candidates = self.roles.search_candidates(keyword)
            if not candidates:
                print(f"[KAC_ROLE_NOT_FOUND] {keyword}")
                continue
            try:
                return self.choose_roles(keyword, candidates)
            except Back:
                continue

    def select_roles_by_tag(self) -> list[KacRole]:
        if not self.tag_lookup_tool:
            print("[TAG_UNAVAILABLE] 태그 검색 도구가 연결되어 있지 않습니다.")
            return []
        assets = self.tag_lookup_tool.select_assets_by_tag("kac", "KAC cluster 태그검색")
        if not assets:
            return []
        found: dict[str, KacRole] = {}
        all_roles = self.roles.list_all()
        for asset in assets:
            terms = [asset.name, asset.cloud_value, asset.cloudprovider_value]
            terms.extend(suggested_search_terms(asset))
            normalized_terms = [term.lower() for term in terms if term]
            for role in all_roles:
                text = role_search_text(role)
                if any(term and term in text for term in normalized_terms):
                    found[role.uuid] = role
        if not found:
            ConsoleView.auto_table(
                ["cluster", "식별값"],
                [[asset.name, " / ".join(suggested_search_terms(asset)[:4]) or "-"] for asset in assets],
                [24, 24],
                [42, 58],
            )
            return []
        return self.choose_roles("tag", list(found.values()))

    def preview_roles(self, keyword: str):
        if not keyword:
            print("[KAC PREVIEW] 검색어를 입력한 뒤 Tab을 누르세요.")
            return
        candidates = self.roles.search_candidates(keyword)
        if not candidates:
            print(f"[KAC PREVIEW] 후보 없음: {keyword}")
            return
        print(f"[KAC PREVIEW] 후보 {len(candidates)}개")
        self.print_role_candidates(candidates[:KAC_CANDIDATE_DISPLAY_LIMIT])
        print("[KAC PREVIEW] 위 표는 미리보기입니다. 선택하려면 같은 검색어에서 Enter를 누르세요.")

    def choose_roles(self, keyword: str, candidates: list[KacRole]) -> list[KacRole]:
        current = candidates
        while True:
            shown = current[:KAC_CANDIDATE_DISPLAY_LIMIT]
            print(f"\n  {keyword}: KAC role 후보 {len(current)}개")
            self.print_role_candidates(shown)
            if len(current) > len(shown):
                print(f"  {len(current) - len(shown)}개 더 있음. 검색어를 더 좁히세요.")
            selected = read_value("    번호 선택(1 / 1,2 / a=표시된 전체) 또는 추가 검색어, /b=다시 검색: ")
            numbers = parse_number_selection(selected, len(shown))
            if numbers:
                selected_roles = [shown[number - 1] for number in numbers]
                ConsoleView.table(["선택 KAC role"], [[role.name] for role in selected_roles], [80])
                return selected_roles
            if selected.strip().isdigit():
                print("    잘못된 번호입니다.")
                continue
            refined = [
                role
                for role in current
                if all(term in role_search_text(role) for term in selected.lower().split())
            ]
            if not refined:
                print(f"[KAC_ROLE_REFINE_NOT_FOUND] {selected}")
                continue
            current = refined

    @staticmethod
    def print_role_candidates(roles: list[KacRole]):
        rows = []
        for idx, role in enumerate(roles, 1):
            parts = kac_role_parts(role)
            rows.append([
                str(idx),
                parts["kind"],
                parts["csp"] or "-",
                parts["account"] or "-",
                parts["cluster"] or "-",
                parts["namespace"] or "-",
                role.name,
            ])
        ConsoleView.auto_table(
            ["번호", "권한", "CSP", "account", "cluster", "namespace", "role"],
            rows,
            [4, 6, 5, 12, 18, 12, 28],
            [4, 8, 6, 14, 28, 22, 46],
        )

    def read_target_users(self, title: str) -> list[User]:
        while True:
            print(f"\n{title}")
            raw_values = read_user_inputs()
            if not raw_values:
                return []
            users, unresolved = self.resolver.resolve_user_inputs(raw_values)
            if unresolved:
                print("[USER_INPUT_RETRY] 찾지 못한 사용자가 있어 사용자 입력 단계로 돌아갑니다.")
                ConsoleView.table(["NOT_FOUND"], [[item] for item in unresolved], [40])
                continue
            return users

    def build_grant_targets(self, roles: list[KacRole]) -> tuple[dict[str, list[User]], list[RolePlanEntry]]:
        targets_by_role: dict[str, list[User]] = {role.uuid: [] for role in roles}
        entries: list[RolePlanEntry] = []
        seen: set[str] = set()
        users = self.read_target_users("KAC role 부여 대상 사용자를 입력하세요.")
        unique_users: list[User] = []
        for user in users:
            if user.uuid in seen:
                entries.append(RolePlanEntry("제외", user, "-", "제외", "중복 입력"))
                continue
            seen.add(user.uuid)
            unique_users.append(user)

        for user in unique_users:
            current_roles = self.user_roles(user)
            for role in roles:
                exists = self.role_exists(current_roles, role)
                targets_by_role[role.uuid].append(user)
                note = "기존 권한 갱신" if exists else ""
                entries.append(RolePlanEntry("대상", user, role.name, "부여" if not exists else "재부여/갱신", note))
        return targets_by_role, entries

    def build_revoke_targets_from_assigned(
        self,
        users: list[User],
    ) -> tuple[list[KacRole], dict[str, list[User]], list[RolePlanEntry]]:
        assigned_rows: list[tuple[User, KacRole]] = []
        for user in users:
            roles = self.user_roles(user)
            if not roles:
                print(f"  - {user.name}: 회수 가능한 KAC role 없음")
                continue
            for role in roles:
                assigned_rows.append((user, role))
        selected_pairs = self.choose_revoke_role_pairs(assigned_rows)
        roles_by_uuid: dict[str, KacRole] = {}
        targets_by_role: dict[str, list[User]] = {}
        entries: list[RolePlanEntry] = []
        seen_pairs: set[tuple[str, str]] = set()
        for user, role in selected_pairs:
            pair_key = (user.uuid, role.uuid)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)
            roles_by_uuid[role.uuid] = role
            targets_by_role.setdefault(role.uuid, []).append(user)
            entries.append(RolePlanEntry("대상", user, role.name, "회수"))
        roles = list(roles_by_uuid.values())
        for role in roles:
            targets_by_role.setdefault(role.uuid, [])
        return roles, targets_by_role, entries

    def choose_revoke_role_pairs(self, assigned_rows: list[tuple[User, KacRole]]) -> list[tuple[User, KacRole]]:
        if not assigned_rows:
            return []
        current = assigned_rows
        while True:
            rows = []
            for idx, (user, role) in enumerate(current, 1):
                parts = kac_role_parts(role)
                rows.append([
                    str(idx),
                    user.name,
                    parts["kind"],
                    parts["account"] or "-",
                    parts["cluster"] or "-",
                    role.name,
                ])
            print("\n[KAC REVOKE] 현재 부여된 role 중 회수 대상을 선택하세요.")
            ConsoleView.auto_table(
                ["번호", "사용자", "권한", "account", "cluster", "role"],
                rows,
                [4, 12, 6, 12, 18, 28],
                [4, 24, 8, 14, 28, 64],
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
                    item[0].name,
                    item[1].name,
                    item[1].description,
                    " ".join(item[1].policies or []),
                ]).lower()
            ]
            if not narrowed:
                print(f"[KAC_REVOKE_REFINE_NOT_FOUND] {value}")
                continue
            current = narrowed

    def precheck_roles_against_csv(self, roles: list[KacRole]) -> bool:
        """변경 API 호출 전에 CSV KAC role 후보가 현재 API 값과 같은지 확인합니다."""

        rows: list[list[str]] = []
        failed = False
        api_roles = None
        for role in roles:
            csv_role = self.roles.local_reference.kac_role_reference(role)
            if not csv_role:
                continue
            if api_roles is None:
                api_roles = self.roles.list_all_api()
            api_role = next(
                (
                    item
                    for item in api_roles
                    if item.uuid == csv_role.uuid or item.name.lower() == csv_role.name.lower()
                ),
                None,
            )
            ok = bool(api_role and api_role.uuid == csv_role.uuid and api_role.name.lower() == csv_role.name.lower())
            if not ok:
                failed = True
            rows.append([
                "OK" if ok else "FAIL",
                csv_role.name,
                csv_role.uuid,
                api_role.uuid if api_role else "-",
            ])
        if rows:
            print("\nKAC CSV/API 사전 검증")
            ConsoleView.auto_table(["검증", "role", "CSV uuid", "API uuid"], rows, [6, 36, 36, 36], [6, 56, 38, 38])
        return not failed

    def execute(
        self,
        action: str,
        roles: list[KacRole],
        expiry: str,
        targets_by_role: dict[str, list[User]],
    ) -> dict[str, list[User]]:
        verified_by_role: dict[str, list[User]] = {role.uuid: [] for role in roles}
        users_by_uuid: dict[str, User] = {}
        role_uuids_by_user: dict[str, list[str]] = {}
        for role in roles:
            for user in targets_by_role.get(role.uuid, []):
                users_by_uuid[user.uuid] = user
                role_uuids_by_user.setdefault(user.uuid, []).append(role.uuid)

        for user_uuid, role_uuids in role_uuids_by_user.items():
            user = users_by_uuid[user_uuid]
            if action == "grant":
                body = {"roleUuids": role_uuids, "expirationDate": kac_expiration_date(expiry)}
                self.client.request("POST", f"/api/external/v2/kac/access-controls/users/{user.uuid}/roles", body)
            else:
                body = {"roleUuids": role_uuids}
                self.client.request("DELETE", f"/api/external/v2/kac/access-controls/users/{user.uuid}/roles", body)
            current_roles = self.user_roles(user, refresh=True)
            for role in roles:
                if role.uuid not in role_uuids:
                    continue
                ok = self.role_exists(current_roles, role) is (action == "grant")
                if ok:
                    verified_by_role[role.uuid].append(user)
        return verified_by_role

    def user_has_role(self, user: User, role: KacRole) -> bool:
        return self.role_exists(self.user_roles(user), role)

    def user_roles(self, user: User, refresh: bool = False) -> list[KacRole]:
        if not refresh and user.uuid in self.user_role_cache:
            print(f"[KAC USER ROLE CACHE] {user.name}")
            return list(self.user_role_cache[user.uuid])
        data = self.client.request("GET", f"/api/external/v2/kac/access-controls/users/{user.uuid}/roles")
        roles = [to_kac_role(item) for item in response_list(data)]
        self.user_role_cache[user.uuid] = roles
        return list(roles)

    @staticmethod
    def role_exists(roles: list[KacRole], target: KacRole) -> bool:
        return any(role.uuid == target.uuid or role.name.lower() == target.name.lower() for role in roles)

    @staticmethod
    def print_plan(action: str, roles: list[KacRole], entries: list[RolePlanEntry], expiry: str):
        targets = [entry for entry in entries if entry.kind == "대상"]
        skips = [entry for entry in entries if entry.kind == "제외"]
        rows = [
            ["작업", "부여" if action == "grant" else "회수"],
            ["role 수", f"{len(roles)}개"],
            ["대상", f"{len(targets)}건"],
            ["제외", f"{len(skips)}건"],
        ]
        if expiry:
            rows.append(["만료일", expiry])
        label = "부여" if action == "grant" else "회수"
        print(f"\n[OPERATION] KAC role {label}")
        print("KAC 실행 계획")
        ConsoleView.table(["항목", "값"], rows, [8, 72])
        role_rows = [[role.name, ", ".join(role.policies or []) or "-"] for role in roles]
        ConsoleView.table(["role", "policies"], role_rows, [34, 58])
        ConsoleView.table(
            ["구분", "사용자", "role", "처리"],
            [[entry.kind, entry.user.name, entry.role_name, entry.action_text] for entry in entries],
            [6, 18, 38, 34],
        )

    @staticmethod
    def confirm(action: str) -> bool:
        label = "부여" if action == "grant" else "회수"
        while True:
            value = read_value(f"\nKAC role {label}를 실행할까요? [y/N, /b=이전 단계]: ", allow_empty=True).lower()
            if value in ("y", "yes"):
                return True
            if value in ("", "n", "no"):
                return False
            print("y 또는 n을 입력하세요.")

    @staticmethod
    def print_result(
        action: str,
        roles: list[KacRole],
        entries: list[RolePlanEntry],
        verified_by_role: dict[str, list[User]],
    ):
        done_pairs = {
            (role_uuid, user.uuid)
            for role_uuid, users in verified_by_role.items()
            for user in users
        }
        rows = []
        for entry in entries:
            matched_role = next((role for role in roles if role.name == entry.role_name), None)
            done = matched_role and (matched_role.uuid, entry.user.uuid) in done_pairs
            rows.append(["완료" if done else entry.kind, entry.user.name, entry.role_name, entry.action_text])
        label = "KAC role 부여 검증" if action == "grant" else "KAC role 회수 검증"
        summary = [[label, role.name, f"{len(verified_by_role.get(role.uuid, []))}명"] for role in roles]
        ConsoleView.table(["결과", "role", "완료"], summary, [18, 42, 8])
        ConsoleView.table(["구분", "사용자", "role", "처리"], rows, [6, 18, 38, 34])
