from __future__ import annotations

from dataclasses import dataclass


class Back(Exception):
    """이전 작업/선택 흐름으로 돌아갑니다."""


class Quit(Exception):
    """프로그램을 종료합니다."""


@dataclass
class User:
    uuid: str
    name: str
    login_id: str
    email: str
    domain_type: str


@dataclass
class Role:
    uuid: str
    name: str


@dataclass
class RoleInfo:
    csp: str
    env: str
    role_type: str
    hint: str


@dataclass
class RolePlanEntry:
    kind: str
    user: User
    role_name: str
    action: str
    note: str = ""

    @property
    def action_text(self) -> str:
        return self.action if not self.note else f"{self.action} ({self.note})"


@dataclass
class ReportContext:
    ticket: str
    division: str
    team: str
    requester: str
    system_name: str
    service: str


@dataclass
class ServerGroup:
    uuid: str
    name: str
    description: str = ""


@dataclass
class SecretStore:
    uuid: str
    name: str


@dataclass
class OsAccountRequest:
    server_group: ServerGroup
    secret_store: SecretStore
    vault_role_name: str
    accounts: list[str]


@dataclass
class DacConnection:
    # uuid는 DAC grant API에 넣는 clusterUuid입니다.
    # connection_uuid는 DB connection group 조회/상세조회에 쓰는 UUID입니다.
    uuid: str
    name: str
    database_type: str
    connection_uuid: str = ""
    cloud_provider_type: str = ""
    endpoints: list[str] | None = None
    cluster_type: str = ""
    deleted: bool = False


@dataclass
class DacPrivilege:
    uuid: str
    name: str
    vendor: str
    status: str
    privilege_types: list[str]


@dataclass
class KacRole:
    uuid: str
    name: str
    description: str = ""
    policies: list[str] | None = None
