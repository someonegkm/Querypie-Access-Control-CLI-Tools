from __future__ import annotations

from .asset_tags import (
    AssetIdentity,
    asset_matches_keyword,
    asset_matches_key_value,
    identity_to_row,
    normalize_asset_identity,
    normalize_key,
    suggested_search_terms,
    tag_summary,
)
from .config import MAX_TAG_LOOKUP_SCAN_PAGES, TAG_LOOKUP_DISPLAY_LIMIT, TAG_LOOKUP_PAGE_SIZE, RuntimeConfig
from .asset_reference import LocalAssetReference
from .io_utils import read_defaulted, read_value
from .models import Back
from .api_utils import page_numbers, parse_number_selection, quote, response_list, warn_scan_limit
from .sac_role_utils import to_role
from .view import ConsoleView


class TagLookupRepository:
    """SAC/DAC/KAC 자산의 태그를 읽어 공통 AssetIdentity로 변환한다."""

    def __init__(self, client):
        self.client = client
        self.local_reference = LocalAssetReference()
        self.detail_cache: dict[str, dict] = {}
        self.asset_cache: dict[str, list[AssetIdentity]] = {}

    def get_detail(self, path: str, uuid: str) -> dict:
        cache_key = f"{path}:{uuid}"
        if cache_key not in self.detail_cache:
            try:
                data = self.client.request("GET", path.format(uuid=uuid))
                self.detail_cache[cache_key] = data if isinstance(data, dict) else {}
            except Exception:
                self.detail_cache[cache_key] = {}
        return self.detail_cache[cache_key]

    def scan_sac_server_groups(self, force_api: bool = False) -> list[AssetIdentity]:
        local_assets = [] if force_api else self.local_reference.tag_assets("sac")
        if local_assets:
            print(f"[LOCAL TAG] SAC 태그 CSV 참조 {len(local_assets)}개 사용")
            return local_assets
        if "sac" in self.asset_cache:
            print(f"[TAG CACHE] SAC scan cache {len(self.asset_cache['sac'])}개 사용")
            return list(self.asset_cache["sac"])
        assets: list[AssetIdentity] = []
        for page in page_numbers(MAX_TAG_LOOKUP_SCAN_PAGES):
            data = self.client.request(
                "GET",
                "/api/external/v2/sac/server-groups",
                params={"pageNumber": page, "pageSize": TAG_LOOKUP_PAGE_SIZE},
            )
            items = response_list(data)
            if not items:
                break
            for item in items:
                uuid = str(item.get("uuid") or item.get("serverGroupUuid") or "")
                # OpenAPI 기준 SAC server-group 목록에는 filterTags가 포함됩니다.
                # 목록 item에 tag가 없을 때만 detail을 추가로 조회합니다.
                needs_detail = not item.get("filterTags") and not item.get("tags")
                detail = self.get_detail("/api/external/v2/sac/server-groups/{uuid}", uuid) if uuid and needs_detail else {}
                assets.append(normalize_asset_identity("SAC", "server-group", detail or item))
            page_data = data.get("page", {}) if isinstance(data, dict) else {}
            total_pages = int(page_data.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < TAG_LOOKUP_PAGE_SIZE:
                break
        else:
            warn_scan_limit("SAC tag lookup scan", MAX_TAG_LOOKUP_SCAN_PAGES, TAG_LOOKUP_PAGE_SIZE)
        self.asset_cache["sac"] = assets
        return assets

    def scan_dac_connections(self, force_api: bool = False) -> list[AssetIdentity]:
        local_assets = [] if force_api else self.local_reference.tag_assets("dac")
        if local_assets:
            print(f"[LOCAL TAG] DAC 태그 CSV 참조 {len(local_assets)}개 사용")
            return local_assets
        if "dac" in self.asset_cache:
            print(f"[TAG CACHE] DAC scan cache {len(self.asset_cache['dac'])}개 사용")
            return list(self.asset_cache["dac"])
        assets: list[AssetIdentity] = []
        for page in page_numbers(MAX_TAG_LOOKUP_SCAN_PAGES):
            data = self.client.request(
                "GET",
                f"/api/external/v2/dac/connections?pageNumber={page}&pageSize={TAG_LOOKUP_PAGE_SIZE}",
            )
            items = response_list(data)
            if not items:
                break
            for item in items:
                uuid = str(item.get("uuid") or "")
                # DAC connection 목록 응답에는 tags가 없습니다. detail GET에서 tags와 clusters를 받습니다.
                detail = self.get_detail("/api/external/v2/dac/connections/{uuid}", uuid) if uuid else {}
                assets.append(normalize_asset_identity("DAC", "db-connection", detail or item))
            page_data = data.get("page", {}) if isinstance(data, dict) else {}
            total_pages = int(page_data.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < TAG_LOOKUP_PAGE_SIZE:
                break
        else:
            warn_scan_limit("DAC tag lookup scan", MAX_TAG_LOOKUP_SCAN_PAGES, TAG_LOOKUP_PAGE_SIZE)
        self.asset_cache["dac"] = assets
        return assets

    def scan_kac_clusters(self, force_api: bool = False) -> list[AssetIdentity]:
        local_assets = [] if force_api else self.local_reference.tag_assets("kac")
        if local_assets:
            print(f"[LOCAL TAG] KAC 태그 CSV 참조 {len(local_assets)}개 사용")
            return local_assets
        if "kac" in self.asset_cache:
            print(f"[TAG CACHE] KAC scan cache {len(self.asset_cache['kac'])}개 사용")
            return list(self.asset_cache["kac"])
        assets: list[AssetIdentity] = []
        for page in page_numbers(MAX_TAG_LOOKUP_SCAN_PAGES):
            data = self.client.request(
                "GET",
                "/api/external/v2/kac/clusters",
                params={"pageNumber": page, "pageSize": TAG_LOOKUP_PAGE_SIZE},
            )
            items = response_list(data)
            if not items:
                break
            for item in items:
                uuid = str(item.get("uuid") or item.get("clusterUuid") or "")
                # OpenAPI 기준 KAC cluster 목록에는 tags가 포함됩니다.
                # 목록 응답에 tag가 없을 때만 detail 조회를 시도합니다.
                needs_detail = not item.get("tags")
                detail = self.get_detail("/api/external/v2/kac/clusters/{uuid}", uuid) if uuid and needs_detail else {}
                assets.append(normalize_asset_identity("KAC", "cluster", detail or item))
            page_data = data.get("paging", data.get("page", {})) if isinstance(data, dict) else {}
            total_pages = int(page_data.get("totalPages", 0) or 0)
            if total_pages and page + 1 >= total_pages:
                break
            if len(items) < TAG_LOOKUP_PAGE_SIZE:
                break
        else:
            warn_scan_limit("KAC tag lookup scan", MAX_TAG_LOOKUP_SCAN_PAGES, TAG_LOOKUP_PAGE_SIZE)
        self.asset_cache["kac"] = assets
        return assets


class TagLookupTool:
    """SAC/DAC/KAC API 태그 기준으로 검색 후보를 찾는 조회 도구."""

    def __init__(self, client, runtime: RuntimeConfig):
        self.client = client
        self.runtime = runtime
        self.repository = TagLookupRepository(client)
        self.query_cache: dict[tuple[str, str, str, str], list[AssetIdentity]] = {}

    def run(self):
        scope = read_defaulted("조회범위(all/sac/dac/kac)", "all").lower()
        if scope not in ("all", "sac", "dac", "kac"):
            print("[TAG_SCOPE] 조회범위는 all, sac, dac, kac 중 하나를 입력하세요.")
            return
        self.run_scope(scope)

    def run_scope(self, scope: str):
        assets = self.select_assets_by_tag(scope, title="태그 조회", allow_empty_result=False)
        if not assets:
            return
        if scope == "sac":
            self.print_sac_assets("선택 태그", assets)
        else:
            self.print_assets("선택 태그", assets)

    def select_assets_by_tag(
        self,
        scope: str,
        title: str,
        allow_empty_result: bool = True,
        asset_filter=None,
        filter_message: str = "",
    ) -> list[AssetIdentity]:
        scope_label = "SAC/DAC/KAC 전체" if scope == "all" else scope.upper()
        print(f"[TAG_SCOPE] 조회 범위: {scope_label}")
        assets = self.scan_assets(scope)
        if not assets:
            print(f"[TAG_EMPTY] {scope} 조회 결과가 없습니다.")
            return []
        if asset_filter:
            before = len(assets)
            assets = [asset for asset in assets if asset_filter(asset)]
            removed = before - len(assets)
            if removed and filter_message:
                print(f"[TAG_FILTER] {filter_message}: {removed}개 제외")
            if not assets:
                print(f"[TAG_EMPTY] {scope} 조회 결과 중 선택 가능한 대상이 없습니다.")
                return []
        key_options = self.print_tag_key_options(assets)
        while True:
            key = self.read_tag_key(key_options)
            while True:
                try:
                    self.print_tag_value_options(assets, key)
                    value = read_value("태그 value(부분값 가능, all/빈 값=해당 key 전체, /b=key 선택): ", allow_empty=True) or "all"
                except Back:
                    break
                label = f"{key}={value}"
                candidates = self.cached_filter(scope, key, value, assets, "local")
                if not candidates:
                    api_assets = self.scan_assets(scope, force_api=True)
                    candidates = self.cached_filter(scope, key, value, api_assets, "api")
                    if candidates:
                        print("[TAG FALLBACK] CSV/cache에서 찾지 못해 API scan cache까지 확인했습니다.")
                if not candidates:
                    print(f"[TAG_NOT_FOUND] {label}")
                    continue
                try:
                    selected = self.choose_assets(title, label, candidates)
                except Back:
                    continue
                if not selected and not allow_empty_result:
                    return []
                return selected

    def cached_filter(
        self,
        scope: str,
        key: str,
        value: str,
        assets: list[AssetIdentity],
        source: str,
    ) -> list[AssetIdentity]:
        cache_key = (scope, normalize_key(key), value.strip().lower(), source)
        if cache_key in self.query_cache:
            print(f"[TAG CACHE] {key}={value} filter cache {len(self.query_cache[cache_key])}개 사용")
            return list(self.query_cache[cache_key])
        candidates = [asset for asset in assets if asset_matches_key_value(asset, key, value)]
        self.query_cache[cache_key] = candidates
        return list(candidates)

    def scan_assets(self, scope: str, force_api: bool = False) -> list[AssetIdentity]:
        assets: list[AssetIdentity] = []
        if scope in ("all", "sac"):
            self.safe_scan("SAC", lambda: self.repository.scan_sac_server_groups(force_api=force_api), assets)
        if scope in ("all", "dac"):
            self.safe_scan("DAC", lambda: self.repository.scan_dac_connections(force_api=force_api), assets)
        if scope in ("all", "kac"):
            self.safe_scan("KAC", lambda: self.repository.scan_kac_clusters(force_api=force_api), assets)
        return assets

    @staticmethod
    def print_tag_key_options(assets: list[AssetIdentity]) -> list[str]:
        options = tag_key_options(assets)
        rows = []
        for idx, item in enumerate(options, 1):
            rows.append([
                str(idx),
                item["key"],
                item["count"],
                item["values"],
                item["note"],
            ])
        print("\n조회 가능한 태그 key")
        print("표의 번호를 선택하거나, 표에 없는 실제 tag key를 직접 입력할 수 있습니다.")
        ConsoleView.auto_table(
            ["번호", "key", "건수", "값 예시", "추천"],
            rows,
            [4, 16, 6, 24, 8],
            [4, 28, 6, 54, 16],
        )
        return [item["key"] for item in options]

    @staticmethod
    def print_tag_value_options(assets: list[AssetIdentity], key: str):
        key_norm = normalize_key(key)
        if key_norm == "all":
            print("[TAG VALUE] 전체 검색에서는 value에 객체명, account/project, vpc, env 일부를 입력할 수 있습니다.")
            return
        values: list[str] = []
        for asset in assets:
            for tag in asset.tags or []:
                tag_key = normalize_key(tag.key)
                if (key_norm == tag_key or key_norm in tag_key) and tag.value and tag.value not in values:
                    values.append(tag.value)
                if len(values) >= 12:
                    break
            if len(values) >= 12:
                break
        if not values:
            print("[TAG VALUE] 값 예시가 없습니다. 실제 value 일부를 직접 입력할 수 있습니다.")
            return
        ConsoleView.auto_table(
            ["value 예시"],
            [[value] for value in values],
            [24],
            [80],
        )

    @staticmethod
    def choose_assets(title: str, label: str, assets: list[AssetIdentity]) -> list[AssetIdentity]:
        current = assets
        while True:
            shown = current[:TAG_LOOKUP_DISPLAY_LIMIT]
            print(f"\n[{title}] {label}: 후보 {len(current)}개")
            rows = []
            for idx, asset in enumerate(shown, 1):
                row = identity_to_row(asset)
                rows.append([
                    str(idx),
                    row["product"],
                    row["asset_name"],
                    row["csp"] or "-",
                    row["cloud_tag_value"] or "-",
                    row["vpc_id"] or "-",
                    tag_summary(asset),
                ])
            ConsoleView.auto_table(
                ["번호", "구분", "객체", "CSP", "account/project", "vpc", "식별태그"],
                rows,
                [4, 4, 24, 5, 16, 14, 28],
                [4, 4, 42, 6, 18, 18, 58],
            )
            if len(current) > len(shown):
                print(f"  {len(current) - len(shown)}개 더 있음. 태그 key/value를 더 좁혀서 다시 실행하세요.")
            value = read_value("객체 선택(1 / 1,2 / a=표시된 전체 / s=건너뛰기) 또는 추가 검색어, /b=value 선택: ")
            if value.lower() in ("s", "skip", "건너뛰기"):
                return []
            numbers = parse_number_selection(value, len(shown))
            if numbers:
                return [shown[number - 1] for number in numbers]
            if value.strip().isdigit():
                print("잘못된 번호입니다.")
                continue
            narrowed = [asset for asset in current if asset_matches_keyword(asset, value)]
            if not narrowed:
                print(f"[TAG_REFINE_NOT_FOUND] {value}")
                continue
            current = narrowed

    @staticmethod
    def read_tag_key(options: list[str]) -> str:
        while True:
            value = read_value("태그 key 번호/이름 또는 직접 key 입력(all=전체): ", allow_empty=True) or "all"
            if value.isdigit() and 1 <= int(value) <= len(options):
                return options[int(value) - 1]
            if value:
                return value

    @staticmethod
    def safe_scan(label: str, scan_func, assets: list[AssetIdentity]):
        try:
            assets.extend(scan_func())
        except Exception as exc:
            print(f"[TAG_SKIP] {label} 조회 실패: {exc}")

    @staticmethod
    def print_assets(keyword: str, assets: list[AssetIdentity]):
        shown = assets[:TAG_LOOKUP_DISPLAY_LIMIT]
        print(f"\n[TAG LOOKUP] {keyword}: 후보 {len(assets)}개")
        rows = []
        for asset in shown:
            row = identity_to_row(asset)
            rows.append([
                row["product"],
                row["asset_name"],
                row["csp"] or "-",
                row["cloud_tag_value"] or "-",
                row["vpc_id"] or "-",
                tag_summary(asset),
                " / ".join(suggested_search_terms(asset)[:4]) or "-",
            ])
        ConsoleView.auto_table(
            ["구분", "자산", "CSP", "account/project", "vpc", "주요태그", "추천검색어"],
            rows,
            [4, 24, 5, 16, 14, 28, 24],
            [4, 38, 6, 18, 18, 56, 40],
        )
        if len(assets) > len(shown):
            print(f"  {len(assets) - len(shown)}개 더 있음. 검색어를 더 좁히세요.")

    def print_sac_assets(self, keyword: str, assets: list[AssetIdentity]):
        shown = assets[:TAG_LOOKUP_DISPLAY_LIMIT]
        print(f"\n[SAC TAG LOOKUP] {keyword}: 서버그룹 후보 {len(assets)}개")
        rows = []
        for asset in shown:
            row = identity_to_row(asset)
            rows.append([
                row["asset_name"],
                row["cloud_tag_value"] or "-",
                row["vpc_id"] or "-",
                tag_summary(asset),
                " / ".join(self.sac_role_hints(asset)) or "-",
            ])
        ConsoleView.auto_table(
            ["서버그룹", "account/project", "vpc", "주요태그", "role 후보"],
            rows,
            [28, 18, 16, 34, 46],
            [42, 18, 18, 56, 52],
        )
        if len(assets) > len(shown):
            print(f"  {len(assets) - len(shown)}개 더 있음. 검색어를 더 좁히세요.")

    def sac_role_hints(self, asset: AssetIdentity) -> list[str]:
        found: dict[str, str] = {}
        for term in suggested_search_terms(asset)[:4]:
            if not term:
                continue
            try:
                data = self.client.request("GET", f"/api/external/v2/sac/roles?name={quote(term)}")
            except Exception:
                continue
            for item in response_list(data):
                role = to_role(item)
                if role.uuid and role.name:
                    found[role.uuid] = role.name
            if len(found) >= 5:
                break
        return list(found.values())[:5]


def tag_lookup_note(asset: AssetIdentity) -> str:
    filter_tags = [tag for tag in asset.tags or [] if tag.source == "filterTags"]
    if asset.product == "SAC" and asset.asset_type == "server-group":
        if not filter_tags:
            return "filterTag 없음"
        if not asset.cloudprovider_value:
            return "cloudprovider 없음"
        return "그룹기준"
    if not asset.cloudprovider_value:
        return "cloudprovider 없음"
    return "조회참고"


IDENTIFIER_TAG_KEYS = {
    "cloudprovider",
    "cloudprovidername",
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


def tag_key_options(assets: list[AssetIdentity]) -> list[dict[str, str]]:
    grouped: dict[str, dict] = {}
    for asset in assets:
        for tag in asset.tags or []:
            if not tag.key:
                continue
            norm = normalize_key(tag.key)
            if norm not in IDENTIFIER_TAG_KEYS:
                continue
            item = grouped.setdefault(
                norm,
                {"key": tag.key, "count": 0, "values": [], "note": ""},
            )
            item["count"] += 1
            if tag.value and tag.value not in item["values"]:
                item["values"].append(tag.value)
            if norm in IDENTIFIER_TAG_KEYS:
                item["note"] = "식별 추천"
    rows = []
    for item in grouped.values():
        values = item["values"][:4]
        rows.append({
            "key": item["key"],
            "count": str(item["count"]),
            "values": " / ".join(values) or "-",
            "note": item["note"] or "-",
        })
    rows.sort(key=lambda row: (0 if row["note"] != "-" else 1, row["key"].lower()))
    return [{"key": "all", "count": str(len(assets)), "values": "전체 자산", "note": "전체"}] + rows
