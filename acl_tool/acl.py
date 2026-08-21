from __future__ import annotations

from .config import RuntimeConfig
from .io_utils import read_user_inputs, read_value, run_input_steps
from .models import Back, Role, RolePlanEntry, User
from .report import ReportWriter, read_report_context
from .resolver import Resolver, SacRoleCache
from .api_utils import end_of_day_utc, inclusive_expiry_date, parse_number_selection, quote, response_list
from .sac_role_utils import role_expiry_days, role_expiry_label, selected_role_sensitive_rule, to_role
from .view import ConsoleView


def default_expiry_for_role(role: Role) -> str:
    """시작일을 포함해 User 1년, SuperUser 90일이 되도록 만료일을 계산한다."""

    return inclusive_expiry_date(role_expiry_days(role))


def sac_expiry_at(expiry: str) -> str:
    return end_of_day_utc(expiry)


class AclTool:
    """SAC role grant/revoke 업무 흐름을 담당한다."""

    def __init__(self, client, runtime: RuntimeConfig, sac_role_cache: SacRoleCache | None = None, tag_lookup_tool=None):
        self.client = client
        self.runtime = runtime
        self.sac_role_cache = sac_role_cache or SacRoleCache()
        self.resolver = Resolver(client, self.sac_role_cache, tag_lookup_tool)
        self.report_writer = ReportWriter(runtime)
        self.user_role_cache: dict[str, list[Role]] = {}
        self.role_detail_cache: dict[str, dict] = {}

    def grant(self):
        try:
            state = run_input_steps([
                self.step_select_grant_roles,
                self.step_read_grant_expiry,
                self.step_build_grant_targets,
                self.step_confirm_grant_plan,
            ])
            roles: list[Role] = state["roles"]
            expiry_by_role: dict[str, str] = state["expiry_by_role"]
            targets_by_role: dict[str, list[User]] = state["targets_by_role"]
            entries: list[RolePlanEntry] = state["entries"]
            if not state.get("confirmed"):
                print("실행하지 않았습니다.")
                return

            if not self.precheck_roles_against_csv(roles):
                print("[PRECHECK_FAIL] CSV와 API role 정보가 달라서 SAC role 변경을 중단합니다.")
                return
            verified_by_role: dict[str, list[User]] = {role.uuid: [] for role in roles}
            verification_rows: list[list[str]] = []
            for role in roles:
                body = {"expiryAt": sac_expiry_at(expiry_by_role[role.uuid]), "serverRoleUuids": [role.uuid]}
                for user in targets_by_role.get(role.uuid, []):
                    self.client.request("POST", f"/api/external/v2/sac/access-controls/{user.uuid}/roles", body)
                    ok = self.verify_user_role(user, role, expected=True)
                    if ok:
                        verified_by_role[role.uuid].append(user)
                    verification_rows.append(["OK" if ok else "FAIL", user.name, role.name, user.uuid, role.uuid])
            self.print_role_result("role 부여 결과", roles, verified_by_role, entries)
            self.print_verification("role 부여 검증", verification_rows)

            if any(verified_by_role.values()):
                report_context = read_report_context()
                path = ""
                for role in roles:
                    users = verified_by_role.get(role.uuid, [])
                    if users:
                        path = self.report_writer.append_grants(report_context, role, expiry_by_role[role.uuid], users)
                ConsoleView.table(["CSV 기록"], [[path]], [80])
        except Back:
            print("이전 단계로 돌아갑니다.")

    def revoke(self):
        try:
            state = run_input_steps([
                self.step_select_revoke_targets,
                self.step_confirm_revoke_plan,
            ])
            roles: list[Role] = state["roles"]
            targets_by_role: dict[str, list[User]] = state["targets_by_role"]
            entries: list[RolePlanEntry] = state["entries"]
            if not state.get("confirmed"):
                print("실행하지 않았습니다.")
                return

            if not self.precheck_roles_against_csv(roles):
                print("[PRECHECK_FAIL] CSV와 API role 정보가 달라서 SAC role 변경을 중단합니다.")
                return
            verified_by_role: dict[str, list[User]] = {role.uuid: [] for role in roles}
            verification_rows: list[list[str]] = []
            for role in roles:
                body = {"serverRoleUuids": [role.uuid]}
                for user in targets_by_role.get(role.uuid, []):
                    self.client.request("DELETE", f"/api/external/v2/sac/access-controls/{user.uuid}/roles", body)
                    ok = self.verify_user_role(user, role, expected=False)
                    if ok:
                        verified_by_role[role.uuid].append(user)
                    verification_rows.append(["OK" if ok else "FAIL", user.name, role.name, user.uuid, role.uuid])
            self.print_role_result("role 회수 결과", roles, verified_by_role, entries)
            self.print_verification("role 회수 검증", verification_rows)
        except Back:
            print("이전 단계로 돌아갑니다.")

    def step_select_grant_roles(self, state: dict):
        self.load_sac_role_cache_if_enabled()
        while True:
            roles = self.resolver.select_roles()
            if self.ensure_roles_have_policy(roles):
                state["roles"] = roles
                return
            print("[SAC_POLICY_BLOCK] policy가 없는 role은 부여할 수 없습니다. role을 다시 선택하세요.")

    def step_read_grant_expiry(self, state: dict):
        state["expiry_by_role"] = self.read_expiry_by_role(state["roles"])

    def step_build_grant_targets(self, state: dict):
        targets_by_role, entries = self.build_grant_targets(state["roles"])
        state["targets_by_role"] = targets_by_role
        state["entries"] = entries

    def step_confirm_grant_plan(self, state: dict):
        roles = state["roles"]
        targets_by_role = state["targets_by_role"]
        self.print_role_plan("부여", roles, state["entries"], state["expiry_by_role"])
        if not any(targets_by_role.values()):
            state["confirmed"] = False
            return
        if not self.confirm_partner_superuser(roles, targets_by_role):
            print("중단했습니다.")
            state["confirmed"] = False
            return
        if not self.confirm_selected_sensitive_roles(roles, targets_by_role):
            print("중단했습니다.")
            state["confirmed"] = False
            return
        state["confirmed"] = self.final_confirm("SAC role 부여")

    def step_select_revoke_targets(self, state: dict):
        users = self.read_target_users("SAC role 회수 대상 사용자를 입력하세요.")
        roles, targets_by_role, entries = self.build_revoke_targets_from_assigned(users)
        state["roles"] = roles
        state["targets_by_role"] = targets_by_role
        state["entries"] = entries

    def step_confirm_revoke_plan(self, state: dict):
        roles = state["roles"]
        targets_by_role = state["targets_by_role"]
        self.print_role_plan("회수", roles, state["entries"])
        if not any(targets_by_role.values()):
            state["confirmed"] = False
            return
        if not self.confirm_selected_sensitive_roles(roles, targets_by_role):
            print("중단했습니다.")
            state["confirmed"] = False
            return
        state["confirmed"] = self.final_confirm("SAC role 회수")

    def ensure_sac_role_cache(self):
        if not self.sac_role_cache.loaded:
            self.sac_role_cache.load(self.client)

    def load_sac_role_cache_if_enabled(self):
        """config.py, -fullscan, SAC 메뉴 cache로 켠 경우에만 SAC role 전체 목록을 읽는다."""

        if self.runtime.use_sac_role_cache:
            self.ensure_sac_role_cache()

    def precheck_roles_against_csv(self, roles: list[Role]) -> bool:
        """변경 API 호출 전에 CSV SAC role 후보가 현재 API 값과 같은지 확인합니다."""

        rows: list[list[str]] = []
        failed = False
        for role in roles:
            csv_role = self.resolver.local_reference.sac_role_reference(role)
            if not csv_role:
                continue
            api_role = self.fetch_api_role_by_name(csv_role.name)
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
            print("\nSAC CSV/API 사전 검증")
            ConsoleView.auto_table(["검증", "role", "CSV uuid", "API uuid"], rows, [6, 36, 36, 36], [6, 56, 38, 38])
        return not failed

    def fetch_api_role_by_name(self, name: str) -> Role | None:
        data = self.client.request("GET", f"/api/external/v2/sac/roles?name={quote(name)}")
        for item in response_list(data):
            role = to_role(item)
            if role.uuid and role.name.lower() == name.lower():
                return role
        return None

    def ensure_roles_have_policy(self, roles: list[Role]) -> bool:
        rows: list[list[str]] = []
        blocked = False
        for role in roles:
            policy_state, policy_label = self.role_policy_state(role)
            rows.append([role.name, policy_label])
            if policy_state == "empty":
                blocked = True
        if rows:
            print("\nSAC role policy 사전 확인")
            ConsoleView.auto_table(["role", "policy"], rows, [34, 12], [76, 48])
        return not blocked

    def role_policy_state(self, role: Role) -> tuple[str, str]:
        detail = self.fetch_role_detail(role)
        policy_values: list[str] = []
        saw_policy_field = False
        for key, value in self.iter_policy_fields(detail):
            saw_policy_field = True
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        label = str(item.get("name") or item.get("uuid") or item.get("policyUuid") or "")
                    else:
                        label = str(item or "")
                    if label:
                        policy_values.append(label)
            elif value:
                policy_values.append(str(value))
        if policy_values:
            return "present", ", ".join(policy_values[:4])
        if saw_policy_field:
            return "empty", "없음 - 부여 차단"
        return "unknown", "확인 필드 없음"

    def iter_policy_fields(self, obj) -> list[tuple[str, object]]:
        found: list[tuple[str, object]] = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key)
                if "policy" in key_text.lower():
                    found.append((key_text, value))
                if isinstance(value, (dict, list)):
                    found.extend(self.iter_policy_fields(value))
        elif isinstance(obj, list):
            for item in obj:
                found.extend(self.iter_policy_fields(item))
        return found

    def fetch_role_detail(self, role: Role) -> dict:
        if not role.uuid:
            return {}
        if role.uuid not in self.role_detail_cache:
            try:
                data = self.client.request("GET", f"/api/external/v2/sac/roles/{role.uuid}")
            except Exception as exc:
                print(f"[SAC_POLICY_CHECK_SKIP] {role.name}: detail 조회 실패: {exc}")
                data = {}
            if isinstance(data, dict):
                self.role_detail_cache[role.uuid] = data.get("common", data) if isinstance(data.get("common", data), dict) else data
            else:
                self.role_detail_cache[role.uuid] = {}
        return self.role_detail_cache[role.uuid]

    def read_expiry_by_role(self, roles: list[Role]) -> dict[str, str]:
        if len(roles) == 1:
            role = roles[0]
            default_expiry = default_expiry_for_role(role)
            expiry = read_value(
                f"만료일 YYYY-MM-DD [{default_expiry} | {role_expiry_label(role)}]: ",
                allow_empty=True,
            ) or default_expiry
            return {role.uuid: expiry}

        rows = [[role.name, default_expiry_for_role(role), role_expiry_label(role)] for role in roles]
        ConsoleView.table(["role", "기본 만료일", "기준"], rows, [44, 12, 18])
        common_expiry = read_value("공통 만료일 YYYY-MM-DD [비우면 role별 기본값]: ", allow_empty=True)
        if common_expiry:
            return {role.uuid: common_expiry for role in roles}
        return {role.uuid: default_expiry_for_role(role) for role in roles}

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

    def build_grant_targets(self, roles: list[Role]) -> tuple[dict[str, list[User]], list[RolePlanEntry]]:
        targets_by_role: dict[str, list[User]] = {role.uuid: [] for role in roles}
        entries: list[RolePlanEntry] = []
        seen: set[str] = set()
        users = self.read_target_users("SAC role 부여 대상 사용자를 입력하세요.")
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
                if exists:
                    entries.append(RolePlanEntry("대상", user, role.name, "재부여/갱신", "만료일 갱신 대상"))
                else:
                    entries.append(RolePlanEntry("대상", user, role.name, "신규부여"))
                targets_by_role[role.uuid].append(user)
        return targets_by_role, entries

    def build_revoke_targets_from_assigned(
        self,
        users: list[User],
    ) -> tuple[list[Role], dict[str, list[User]], list[RolePlanEntry]]:
        assigned_rows: list[tuple[User, Role]] = []
        for user in users:
            roles = self.user_roles(user)
            if not roles:
                print(f"  - {user.name}: 회수 가능한 SAC role 없음")
                continue
            for role in roles:
                assigned_rows.append((user, role))
        selected_pairs = self.choose_revoke_role_pairs(assigned_rows)
        roles_by_uuid: dict[str, Role] = {}
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

    def choose_revoke_role_pairs(self, assigned_rows: list[tuple[User, Role]]) -> list[tuple[User, Role]]:
        if not assigned_rows:
            return []
        current = assigned_rows
        while True:
            rows = [
                [str(idx), user.name, role.name]
                for idx, (user, role) in enumerate(current, 1)
            ]
            print("\n[SAC REVOKE] 현재 부여된 role 중 회수 대상을 선택하세요.")
            ConsoleView.auto_table(["번호", "사용자", "role"], rows, [4, 12, 34], [4, 24, 76])
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
                if needle in item[0].name.lower() or needle in item[1].name.lower()
            ]
            if not narrowed:
                print(f"[SAC_REVOKE_REFINE_NOT_FOUND] {value}")
                continue
            current = narrowed

    def user_roles(self, user: User, refresh: bool = False) -> list[Role]:
        if not refresh and user.uuid in self.user_role_cache:
            print(f"[SAC USER ROLE CACHE] {user.name}")
            return list(self.user_role_cache[user.uuid])
        data = self.client.request("GET", f"/api/external/v2/sac/access-controls/{user.uuid}/roles")
        roles = [to_role(item) for item in response_list(data)]
        self.user_role_cache[user.uuid] = roles
        return list(roles)

    @staticmethod
    def role_exists(roles: list[Role], target: Role) -> bool:
        return any(role.uuid == target.uuid or role.name.lower() == target.name.lower() for role in roles)

    def user_has_role(self, user: User, target: Role) -> bool:
        return self.role_exists(self.user_roles(user, refresh=True), target)

    def verify_user_role(self, user: User, role: Role, expected: bool) -> bool:
        """실행 후 GET API로 role 상태를 다시 확인한다.

        expected=True면 grant 후 role이 있어야 성공이고,
        expected=False면 revoke 후 role이 없어야 성공입니다.
        """

        return self.user_has_role(user, role) is expected

    @staticmethod
    def print_verification(title: str, rows: list[list[str]]):
        if rows:
            print(f"\n{title}")
            ConsoleView.auto_table(
                ["검증", "사용자", "role"],
                [row[:3] for row in rows],
                [6, 12, 28],
                [6, 24, 58],
            )

    @staticmethod
    def print_role_plan(
        title: str,
        roles: list[Role],
        entries: list[RolePlanEntry],
        expiry_by_role: dict[str, str] | None = None,
    ):
        targets = [entry for entry in entries if entry.kind == "대상"]
        skips = [entry for entry in entries if entry.kind == "제외"]
        print(f"\n[OPERATION] SAC role {title}")
        print(f"SAC role {title} 실행 계획")
        ConsoleView.table(
            ["항목", "값"],
            [["작업", title], ["role 수", f"{len(roles)}개"], ["대상", f"{len(targets)}건"], ["제외", f"{len(skips)}건"]],
            [10, 72],
        )
        if expiry_by_role:
            expiry_rows = [[role.name, expiry_by_role.get(role.uuid, "-")] for role in roles]
            ConsoleView.table(["role", "만료일"], expiry_rows, [56, 12])
        ConsoleView.table(
            ["구분", "사용자", "role", "처리"],
            [[entry.kind, entry.user.name, entry.role_name, entry.action_text] for entry in entries],
            [6, 18, 38, 34],
        )

    @staticmethod
    def print_role_result(
        title: str,
        roles: list[Role],
        verified_by_role: dict[str, list[User]],
        entries: list[RolePlanEntry],
    ):
        done_pairs = {
            (role_uuid, user.uuid)
            for role_uuid, users in verified_by_role.items()
            for user in users
        }
        summary = [[role.name, f"{len(verified_by_role.get(role.uuid, []))}명"] for role in roles]
        ConsoleView.table(["결과", "완료"], summary, [56, 10])
        rows = []
        for entry in entries:
            matched_role = next((role for role in roles if role.name == entry.role_name), None)
            done = matched_role and (matched_role.uuid, entry.user.uuid) in done_pairs
            rows.append(["완료" if done else entry.kind, entry.user.name, entry.role_name, entry.action_text])
        print(f"\n{title}")
        ConsoleView.table(["구분", "사용자", "role", "처리"], rows, [6, 18, 38, 34])

    def confirm_partner_superuser(self, roles: list[Role], targets_by_role: dict[str, list[User]]) -> bool:
        danger_rows: list[list[str]] = []
        for role in roles:
            if "superuser" not in role.name.lower():
                continue
            for user in targets_by_role.get(role.uuid, []):
                if user.domain_type == "partner":
                    danger_rows.append([user.name, user.email, role.name])
        if not danger_rows:
            return True
        if self.runtime.skip_partner_superuser_confirm:
            print("\n[SKIP WARNING] 설정값으로 협력사 SuperUser 확인을 생략합니다.")
            ConsoleView.table(["사용자", "email", "role"], danger_rows, [18, 34, 42])
            return True
        print("\n주의: 협력사 도메인 사용자에게 SuperUser 권한을 부여하려고 합니다.")
        ConsoleView.table(["사용자", "email", "role"], danger_rows, [18, 34, 42])
        return read_value("\n계속하려면 CONFIRM 입력: ") == "CONFIRM"

    def confirm_selected_sensitive_roles(self, roles: list[Role], targets_by_role: dict[str, list[User]]) -> bool:
        sensitive = [(role, selected_role_sensitive_rule(role)) for role in roles if selected_role_sensitive_rule(role)]
        if not sensitive:
            return True
        if self.runtime.skip_sensitive_role_confirm:
            names = ", ".join(rule["name"] for _, rule in sensitive if rule)
            print(f"\n[SKIP WARNING] 설정값으로 민감 역할 확인을 생략합니다: {names}")
            return True
        print("\n주의: 추가 확인이 필요한 역할입니다.")
        rows = []
        confirm_words = []
        for role, rule in sensitive:
            if not rule:
                continue
            confirm_words.append(rule["confirm"])
            users = targets_by_role.get(role.uuid, [])
            rows.append([rule["name"], role.name, f"{len(users)}명", rule["confirm"]])
        ConsoleView.table(["규칙", "role", "대상", "확인문구"], rows, [22, 44, 8, 18])
        expected = confirm_words[0] if confirm_words else "CONFIRM"
        return read_value(f"계속하려면 {expected} 입력: ") == expected

    def final_confirm(self, operation: str = "SAC role 변경") -> bool:
        if self.runtime.auto_confirm:
            return True
        while True:
            value = read_value(f"\n{operation}을 실제 실행할까요? [y/N, /b=이전 단계]: ", allow_empty=True).lower()
            if value in ("y", "yes"):
                return True
            if value in ("", "n", "no"):
                return False
            print("y 또는 n을 입력하세요.")
