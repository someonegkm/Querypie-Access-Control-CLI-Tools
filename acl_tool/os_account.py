from __future__ import annotations

from .config import RuntimeConfig
from .io_utils import read_csv_items, read_value
from .models import Back, OsAccountRequest, SecretStore, ServerGroup
from .report import ReportWriter, read_report_context
from .api_utils import first, response_list
from .view import ConsoleView


def to_server_group(item: dict) -> ServerGroup:
    return ServerGroup(
        uuid=first(item, "uuid"),
        name=first(item, "name"),
        description=first(item, "description"),
    )


def to_secret_store(item: dict) -> SecretStore:
    return SecretStore(uuid=first(item, "uuid"), name=first(item, "name"))


class ServerGroupRepository:
    def __init__(self, client):
        self.client = client

    def search(self, name: str) -> list[ServerGroup]:
        data = self.client.request(
            "GET",
            "/api/external/v2/sac/server-groups",
            params={"pageNumber": 0, "pageSize": 50, "name": name},
        )
        groups = [to_server_group(item) for item in response_list(data)]
        return [group for group in groups if group.uuid]


class SecretStoreRepository:
    def __init__(self, client):
        self.client = client

    def list_all(self) -> list[SecretStore]:
        data = self.client.request("GET", "/api/external/v2/security/secret-stores")
        stores = [to_secret_store(item) for item in response_list(data)]
        return [store for store in stores if store.uuid]

    def search(self, name: str) -> list[SecretStore]:
        needle = name.lower()
        return [store for store in self.list_all() if needle in store.name.lower()]


class OsAccountTool:
    """Vault SSH CA 방식의 SAC 서버 OS 계정을 등록한다.

    흐름은 입력 -> 계획 출력 -> 등록 API 호출 -> 조회 API 검증 -> CSV 기록 순서입니다.
    DAC/KAC 계정 등록이 나중에 생기면 이 클래스와 비슷한 Tool 클래스를 추가하면 됩니다.
    """

    def __init__(self, client, runtime: RuntimeConfig):
        self.client = client
        self.runtime = runtime
        self.server_groups = ServerGroupRepository(client)
        self.secret_stores = SecretStoreRepository(client)
        self.report_writer = ReportWriter(runtime)

    def run(self):
        try:
            request = self.read_request()
            self.print_plan(request)
            if not self.confirm():
                print("실행하지 않았습니다.")
                return
            self.create_accounts(request)
            verified_accounts, verification_rows = self.verify_accounts(request)
            ConsoleView.table(
                ["결과", "서버그룹", "Secret Store", "등록계정"],
                [["DONE", request.server_group.name, request.secret_store.name, f"{len(verified_accounts)}개"]],
                [10, 24, 24, 10],
            )
            self.print_verification(verification_rows)
            if verified_accounts:
                report_context = read_report_context()
                path = self.report_writer.append_os_accounts(report_context, request, verified_accounts)
                ConsoleView.table(["CSV 기록"], [[path]], [80])
        except Back:
            print("이전 단계로 돌아갑니다.")

    def read_request(self) -> OsAccountRequest:
        server_group = self.select_server_group()
        secret_store = self.select_secret_store()
        vault_role_name = read_value("Vault Role Name: ")
        accounts = self.read_accounts()
        return OsAccountRequest(server_group, secret_store, vault_role_name, accounts)

    def select_server_group(self) -> ServerGroup:
        while True:
            keyword = read_value("서버그룹 이름: ")
            groups = self.server_groups.search(keyword)
            if not groups:
                print(f"[SERVER_GROUP_NOT_FOUND] {keyword}")
                continue
            exact = [group for group in groups if group.name == keyword]
            if len(exact) == 1:
                return exact[0]
            return self.select_server_group_from_candidates(groups)

    def select_server_group_from_candidates(self, groups: list[ServerGroup]) -> ServerGroup:
        while True:
            rows = [[str(idx), group.name, group.description or "-"] for idx, group in enumerate(groups, 1)]
            ConsoleView.auto_table(["번호", "서버그룹", "설명"], rows, [4, 28, 28], [4, 46, 48])
            value = read_value("번호 선택 또는 /b: ")
            if value.isdigit() and 1 <= int(value) <= len(groups):
                return groups[int(value) - 1]
            print("잘못된 번호입니다.")

    def select_secret_store(self) -> SecretStore:
        while True:
            keyword = read_value("Secret Store 이름: ")
            stores = self.secret_stores.search(keyword)
            if not stores:
                print(f"[SECRET_STORE_NOT_FOUND] {keyword}")
                continue
            exact = [store for store in stores if store.name == keyword]
            if len(exact) == 1:
                return exact[0]
            return self.select_secret_store_from_candidates(stores)

    def select_secret_store_from_candidates(self, stores: list[SecretStore]) -> SecretStore:
        while True:
            rows = [[str(idx), store.name] for idx, store in enumerate(stores, 1)]
            ConsoleView.auto_table(["번호", "Secret Store"], rows, [4, 28], [4, 46])
            value = read_value("번호 선택 또는 /b: ")
            if value.isdigit() and 1 <= int(value) <= len(stores):
                return stores[int(value) - 1]
            print("잘못된 번호입니다.")

    @staticmethod
    def read_accounts() -> list[str]:
        print("OS 계정명을 쉼표(,) 또는 줄바꿈으로 입력하세요. 빈 줄이면 입력 종료.")
        accounts: list[str] = []
        while True:
            value = read_value("> ", allow_empty=True)
            if not value:
                break
            accounts.extend(read_csv_items(value))
        if not accounts:
            raise ValueError("OS 계정명이 비어 있습니다.")
        return list(dict.fromkeys(accounts))

    @staticmethod
    def print_plan(request: OsAccountRequest):
        ConsoleView.table(
            ["항목", "값"],
            [
                ["서버그룹", request.server_group.name],
                ["Secret Store", request.secret_store.name],
                ["Vault Role", request.vault_role_name],
                ["OS 계정", ", ".join(request.accounts)],
            ],
            [14, 80],
        )

    @staticmethod
    def confirm() -> bool:
        while True:
            value = read_value("\nOS 계정을 등록할까요? [y/N, /b=취소]: ", allow_empty=True).lower()
            if value in ("y", "yes"):
                return True
            if value in ("", "n", "no"):
                return False
            print("y 또는 n을 입력하세요.")

    def create_accounts(self, request: OsAccountRequest):
        payload = {
            "vaultSshCaList": [
                {
                    "account": account,
                    "secretStoreUuid": request.secret_store.uuid,
                    "vaultRoleName": request.vault_role_name,
                }
                for account in request.accounts
            ]
        }
        return self.client.request(
            "POST",
            f"/api/external/v2/sac/server-groups/{request.server_group.uuid}/accounts/v2",
            payload,
        )

    def list_vault_ssh_ca_accounts(self, server_group_uuid: str) -> list[dict]:
        """서버그룹의 Vault SSH CA 계정 목록을 조회한다.

        OpenAPI v2의 ListServerAccountsV2Response는 vaultSshCaList처럼
        인증 방식별 list를 따로 내려주므로 response_list() 대신 해당 키를 직접 읽습니다.
        """

        data = self.client.request("GET", f"/api/external/v2/sac/server-groups/{server_group_uuid}/accounts/v2")
        if isinstance(data, dict) and isinstance(data.get("vaultSshCaList"), list):
            return [item for item in data["vaultSshCaList"] if isinstance(item, dict)]
        return []

    def verify_accounts(self, request: OsAccountRequest) -> tuple[list[str], list[list[str]]]:
        """등록 후 API 재조회로 OS 계정이 실제 존재하는지 확인한다."""

        items = self.list_vault_ssh_ca_accounts(request.server_group.uuid)
        verified: list[str] = []
        rows: list[list[str]] = []
        for account in request.accounts:
            match = next(
                (
                    item
                    for item in items
                    if item.get("account") == account
                    and item.get("secretStoreUuid") == request.secret_store.uuid
                    and item.get("vaultRoleName") == request.vault_role_name
                ),
                None,
            )
            if match:
                verified.append(account)
                rows.append(["OK", account, request.server_group.name])
            else:
                rows.append(["FAIL", account, request.server_group.name])
        return verified, rows

    @staticmethod
    def print_verification(rows: list[list[str]]):
        if rows:
            print("\nOS 계정등록 검증")
            ConsoleView.auto_table(["검증", "OS계정", "서버그룹"], rows, [6, 18, 24], [6, 24, 46])
