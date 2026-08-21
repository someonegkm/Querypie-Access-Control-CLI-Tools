from __future__ import annotations

from .config import (
    MAX_ROLE_CACHE_PAGES,
    MAX_USER_FALLBACK_SCAN_PAGES,
    ROLE_PAGE_SIZE,
    ROLE_PREVIEW_LIMIT,
    USER_FALLBACK_SCAN_PAGE_SIZE,
    USER_PAGE_SIZE,
)
from .io_utils import read_role_keyword, read_value
from .models import Back, Role, User
from .api_utils import (
    is_full_search,
    normalize_search_key,
    page_numbers,
    parse_number_selection,
    quote,
    response_list,
    warn_scan_limit,
)
from .sac_role_utils import (
    candidate_review_required,
    filter_roles_in_memory,
    parse_role_name,
    role_search_terms,
    to_role,
)
from .user_utils import normalize_user_query, to_user
from .asset_tags import suggested_search_terms
from .asset_reference import LocalAssetReference
from .view import ConsoleView


class SacRoleCache:
    def __init__(self):
        self.roles: list[Role] = []
        self.loaded = False

    def load(self, client):
        roles: dict[str, Role] = {}
        for page in page_numbers(MAX_ROLE_CACHE_PAGES):
            data = client.request("GET", f"/api/external/v2/sac/roles?pageNumber={page}&pageSize={ROLE_PAGE_SIZE}")
            items = response_list(data)
            if not items:
                break
            for item in items:
                role = to_role(item)
                if role.uuid:
                    roles[role.uuid] = role
            pagination = data.get("pagination", {}) if isinstance(data, dict) else {}
            total_pages = int(pagination.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < ROLE_PAGE_SIZE:
                break
        else:
            warn_scan_limit("SAC role cache", MAX_ROLE_CACHE_PAGES, ROLE_PAGE_SIZE)
        self.roles = list(roles.values())
        self.loaded = True
        print(f"[SAC ROLE CACHE] 역할 {len(self.roles)}개 로드 완료")

    def search(self, keyword: str) -> list[Role]:
        if not self.loaded or not keyword.strip():
            return []
        needles = []
        for term in role_search_terms(keyword):
            term = term.lower()
            needles.append(term)
            if term.startswith("vpc-"):
                needles.append(term[4:])
        needles = [item for item in needles if item]
        found: dict[str, Role] = {}
        for role in self.roles:
            info = parse_role_name(role.name)
            haystack = " ".join([role.name.lower(), info.hint.lower(), info.hint.lower().replace("vpc-", "")])
            if any(needle in haystack for needle in needles):
                found[role.uuid] = role
        return list(found.values())

    def preview(self, keyword: str):
        roles = self.search(keyword)
        if not roles:
            print(f"[SAC ROLE CACHE] 후보 없음: {keyword}")
            return
        print(f"[ROLE PREVIEW] 후보 {len(roles)}개")
        ConsoleView.role_candidates(roles[:ROLE_PREVIEW_LIMIT])
        print("[ROLE PREVIEW] 위 표는 미리보기입니다. 선택하려면 같은 검색어에서 Enter를 누르세요.")
        if len(roles) > ROLE_PREVIEW_LIMIT:
            print(f"... {len(roles) - ROLE_PREVIEW_LIMIT}개 더 있음. 검색어를 더 입력하세요.")


class Resolver:
    def __init__(self, client, sac_role_cache: SacRoleCache | None = None, tag_lookup_tool=None):
        self.client = client
        self.sac_role_cache = sac_role_cache
        self.tag_lookup_tool = tag_lookup_tool
        self.local_reference = LocalAssetReference()
        self.role_search_cache: dict[str, list[Role]] = {}
        self.user_search_cache: dict[str, list[User]] = {}

    def fetch_roles(self, keyword: str) -> list[Role]:
        keyword = keyword.strip()
        cache_key = normalize_search_key(keyword)
        if not cache_key:
            print("[ROLE_SEARCH] 빈 검색어는 조회하지 않습니다.")
            return []
        if cache_key in self.role_search_cache:
            print(f"[ROLE CACHE] 검색 cache 사용: {keyword}")
            return list(self.role_search_cache[cache_key])
        if is_full_search(keyword):
            if not self.sac_role_cache:
                self.sac_role_cache = SacRoleCache()
            if not self.sac_role_cache.loaded:
                self.sac_role_cache.load(self.client)
            roles = list(self.sac_role_cache.roles)
            self.role_search_cache[cache_key] = roles
            return list(roles)
        found: dict[str, Role] = {}
        for role in self.local_reference.search_sac_roles(keyword):
            found[role.uuid] = role
        if found:
            print(f"[LOCAL SAC] role CSV 참조에서 후보 {len(found)}개를 찾았습니다.")
            roles = list(found.values())
            self.role_search_cache[cache_key] = roles
            return list(roles)
        if self.sac_role_cache and self.sac_role_cache.loaded:
            for role in self.sac_role_cache.search(keyword):
                found[role.uuid] = role
        if found:
            roles = list(found.values())
            self.role_search_cache[cache_key] = roles
            return list(roles)
        for term in role_search_terms(keyword):
            data = self.client.request("GET", f"/api/external/v2/sac/roles?name={quote(term)}")
            for item in response_list(data):
                role = to_role(item)
                if role.uuid:
                    found[role.uuid] = role
        roles = list(found.values())
        self.role_search_cache[cache_key] = roles
        return list(roles)

    def select_role(self) -> Role:
        return self.select_roles()[0]

    def select_roles(self) -> list[Role]:
        mode = read_value("role 선택 방식 [search/s=이름검색, tag/t=태그검색, 기본 search]: ", allow_empty=True).lower()
        if mode in ("tag", "t", "태그"):
            roles = self.select_roles_by_tag()
            if roles:
                return roles
            print("[ROLE_TAG_NOT_FOUND] 태그로 role 후보를 찾지 못했습니다. 이름검색으로 전환합니다.")
        while True:
            keyword = read_role_keyword("역할 검색값(role명 / vpc-id suffix / project id, Tab=미리보기): ", self.preview_role_candidates)
            roles = self.fetch_roles(keyword)
            if not roles:
                print(f"[ROLE_NOT_FOUND] {keyword}")
                continue
            try:
                return self.select_roles_from_candidates(roles)
            except Back:
                continue

    def select_roles_by_tag(self) -> list[Role]:
        if not self.tag_lookup_tool:
            print("[TAG_UNAVAILABLE] 태그 검색 도구가 연결되어 있지 않습니다.")
            return []
        assets = self.tag_lookup_tool.select_assets_by_tag("sac", "SAC role 태그검색")
        if not assets:
            return []
        found: dict[str, Role] = {}
        for asset in assets:
            terms = suggested_search_terms(asset)
            terms.extend([asset.name, asset.name.replace("-SG", ""), asset.name.replace("-sg", "")])
            for term in terms:
                for role in self.fetch_roles(term):
                    found[role.uuid] = role
        if not found:
            ConsoleView.auto_table(
                ["서버그룹", "식별값"],
                [[asset.name, " / ".join(suggested_search_terms(asset)[:4]) or "-"] for asset in assets],
                [24, 24],
                [42, 58],
            )
            return []
        return self.select_roles_from_candidates(list(found.values()))

    def select_role_from_candidates(self, roles: list[Role]) -> Role:
        return self.select_roles_from_candidates(roles)[0]

    def select_roles_from_candidates(self, roles: list[Role]) -> list[Role]:
        current_roles = roles
        while True:
            print(f"\n[ROLE SELECT] 후보 {len(current_roles)}개")
            ConsoleView.role_candidates(current_roles)
            self.print_role_review_notice(current_roles)
            selected = read_value("번호 선택(1 / 1,2 / a=전체) 또는 추가 검색어, /b=다시 검색: ")
            numbers = parse_number_selection(selected, len(current_roles))
            if numbers:
                selected_roles = [current_roles[number - 1] for number in numbers]
                ConsoleView.table(
                    ["선택 역할"],
                    [[role.name] for role in selected_roles],
                    [80],
                )
                return selected_roles
            if selected.strip().isdigit():
                print("잘못된 번호입니다.")
                continue
            refined = filter_roles_in_memory(current_roles, selected) or self.fetch_roles(selected)
            if not refined:
                print(f"[ROLE_REFINE_NOT_FOUND] 추가 검색어로 후보를 찾지 못했습니다: {selected}")
                continue
            current_roles = refined

    def preview_role_candidates(self, keyword: str):
        if self.sac_role_cache and self.sac_role_cache.loaded:
            self.sac_role_cache.preview(keyword)
            return
        roles = self.fetch_roles(keyword)
        if not roles:
            print(f"[ROLE PREVIEW] 후보 없음: {keyword}")
            return
        print(f"[ROLE PREVIEW] API 후보 {len(roles)}개")
        ConsoleView.role_candidates(roles[:ROLE_PREVIEW_LIMIT])
        print("[ROLE PREVIEW] 위 표는 미리보기입니다. 선택하려면 같은 검색어에서 Enter를 누르세요.")
        if len(roles) > ROLE_PREVIEW_LIMIT:
            print(f"... {len(roles) - ROLE_PREVIEW_LIMIT}개 더 있음. 검색어를 더 입력하세요.")

    @staticmethod
    def print_role_review_notice(roles: list[Role]):
        required, reasons = candidate_review_required(roles)
        if required:
            print("  후보가 넓습니다. 번호를 바로 선택하거나 추가 검색어로 좁힐 수 있습니다.")
            for reason in reasons:
                print(f"  - {reason}")

    def fetch_users(self, keyword: str) -> list[User]:
        keyword = normalize_user_query(keyword)
        cache_key = normalize_search_key(keyword)
        if not cache_key:
            return []
        if cache_key in self.user_search_cache:
            print(f"[USER CACHE] 검색 cache 사용: {keyword}")
            return list(self.user_search_cache[cache_key])
        found: dict[str, User] = {}
        keys = ("email", "loginId", "name") if "@" in keyword else ("name", "loginId", "email")
        for key in keys:
            for user in self.list_users_by_param(key, keyword):
                found[user.uuid] = user
            if found:
                users = list(found.values())
                self.user_search_cache[cache_key] = users
                return list(users)
        for user in self.scan_users_by_text(keyword):
            found[user.uuid] = user
        if found:
            print(f"[FALLBACK] 사용자 목록 스캔으로 사용자를 찾았습니다: {keyword}")
        users = list(found.values())
        self.user_search_cache[cache_key] = users
        return list(users)

    def list_users_by_param(self, key: str, value: str) -> list[User]:
        data = self.client.request("GET", f"/api/external/v3/iam/users?{key}={quote(value)}&pageNumber=0&pageSize={USER_PAGE_SIZE}")
        return [to_user(item) for item in response_list(data) if to_user(item).uuid]

    def scan_users_by_text(self, text: str) -> list[User]:
        needle = text.lower()
        found: dict[str, User] = {}
        for page in page_numbers(MAX_USER_FALLBACK_SCAN_PAGES):
            data = self.client.request("GET", f"/api/external/v3/iam/users?pageNumber={page}&pageSize={USER_FALLBACK_SCAN_PAGE_SIZE}")
            items = response_list(data)
            if not items:
                break
            for item in items:
                user = to_user(item)
                haystack = " ".join([user.name, user.login_id, user.email]).lower()
                if user.uuid and needle in haystack:
                    found[user.uuid] = user
            pagination = data.get("pagination", {}) if isinstance(data, dict) else {}
            total_pages = int(pagination.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
        else:
            warn_scan_limit("사용자 fallback scan", MAX_USER_FALLBACK_SCAN_PAGES, USER_FALLBACK_SCAN_PAGE_SIZE)
        return list(found.values())

    def resolve_users(self, keyword: str) -> list[User]:
        users, _ = self.resolve_user_keyword(keyword)
        return users

    def resolve_user_inputs(self, keywords: list[str]) -> tuple[list[User], list[str]]:
        users: list[User] = []
        unresolved: list[str] = []
        for keyword in keywords:
            selected, status = self.resolve_user_keyword(keyword)
            if status == "not_found":
                unresolved.append(keyword)
            users.extend(selected)
        return users, unresolved

    def resolve_user_keyword(self, keyword: str) -> tuple[list[User], str]:
        users = self.fetch_users(keyword)
        if not users:
            print(f"  - {keyword}: NOT_FOUND")
            return [], "not_found"
        if len(users) == 1:
            ConsoleView.user_resolution(keyword, users[0])
            return users, "found"
        ConsoleView.user_candidates(keyword, users)
        selected = self.choose_users(users)
        return selected, "found" if selected else "skipped"

    @staticmethod
    def choose_users(users: list[User]) -> list[User]:
        while True:
            selected = read_value("    선택 번호(1 / 1,2 / a=전체 / s=건너뛰기 / /b=현재 job 취소): ")
            if selected.lower() in ("s", "skip", "건너뛰기"):
                print("    -> 건너뜀")
                return []
            numbers = parse_number_selection(selected, len(users))
            if numbers:
                selected_users = [users[number - 1] for number in numbers]
                ConsoleView.selected_users(selected_users)
                return selected_users
            print("    잘못된 번호입니다. 예: 1 또는 1,2 또는 a")
