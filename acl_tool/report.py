from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from datetime import date

from .config import REPORT_DEFAULTS, REPORT_DIR, REPORT_HEADERS, RuntimeConfig
from .io_utils import read_defaulted
from .local_reference import LocalReferenceIndex
from .models import DacConnection, DacPrivilege, KacRole, OsAccountRequest, ReportContext, Role, User
from .api_utils import parse_number_selection
from .sac_role_utils import role_csp_label, role_type_label
from .view import ConsoleView

SAC_ROLE_GRANT_DESCRIPTION = "SAC access request processed"
SAC_OS_ACCOUNT_DESCRIPTION = "SAC OS account request processed"
DAC_GRANT_DESCRIPTION = "DAC access request processed"
KAC_GRANT_DESCRIPTION = "KAC access request processed"
REQUEST_TYPE_GRANT = "권한요청"
REQUEST_TYPE_OS_ACCOUNT = "OS계정등록"
REPORT_STATUS_DONE = "완료"


@dataclass
class ReportRecord:
    """CSV 한 줄에 들어갈 업무별 값.

    공통 신청 정보는 ReportContext가 들고 있고, 이 클래스는 SAC/DAC/OS
    업무마다 달라지는 분류, CSP, 권한, 내용, 기간, 비고 값을 들고 있습니다.
    """

    requester: str
    request_type: str
    csp: str
    permission: str
    service: str
    content: str
    period: str
    note: str = ""


class ReportWriter:
    """Excel 호환 CSV에 성공 검증된 이력을 append하는 클래스."""

    def __init__(self, runtime: RuntimeConfig):
        self.runtime = runtime

    def file_path(self, product: str) -> str:
        if self.runtime.report_file:
            directory = os.path.dirname(self.runtime.report_file)
            if directory:
                os.makedirs(directory, exist_ok=True)
            return self.runtime.report_file

        today = date.today()
        os.makedirs(REPORT_DIR, exist_ok=True)
        product_label = product.upper()
        if self.runtime.report_period == "week":
            year, week, _ = today.isocalendar()
            name = f"AccessPlatform_{product_label}_Access_Report_{year}-W{week:02d}.csv"
        else:
            name = f"AccessPlatform_{product_label}_Access_Report_{today.isoformat()}.csv"
        return os.path.join(REPORT_DIR, name)

    def append_records(self, context: ReportContext, records: list[ReportRecord], product: str) -> str:
        path = self.file_path(product)
        write_header = not os.path.exists(path) or os.path.getsize(path) == 0
        today = date.today().isoformat()

        with open(path, "a", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(REPORT_HEADERS)
            for record in records:
                writer.writerow([
                    context.ticket,         # 티켓
                    today,                  # 요청일
                    today,                  # 처리일
                    context.division,       # 부문
                    context.team,           # 부서명
                    record.requester,       # 접수자
                    context.system_name,    # 접수형태
                    record.request_type,    # 분류
                    record.csp,             # CSP
                    record.permission,      # 권한
                    record.service,         # 시스템/서비스명
                    self.runtime.csv_env,   # 환경
                    record.content,         # 내용
                    record.period,          # 기간
                    REPORT_STATUS_DONE,     # 상태
                    record.note,            # 비고
                ])
        return path

    def append_grants(self, context: ReportContext, role: Role, expiry: str, users: list[User]) -> str:
        today = date.today().isoformat()
        period = f"{today} ~ {expiry}"
        records = [
            ReportRecord(
                requester=context.requester or user.name,
                request_type=REQUEST_TYPE_GRANT,
                csp=role_csp_label(role),
                permission=role_type_label(role),
                service=context.service,
                content=role.name,
                period=period,
                note=SAC_ROLE_GRANT_DESCRIPTION,
            )
            for user in users
        ]
        return self.append_records(context, records, "SAC")

    def append_os_accounts(self, context: ReportContext, request: OsAccountRequest, accounts: list[str]) -> str:
        """SAC 서버 OS 계정등록 성공 건만 CSV에 쓴다."""

        records = [
            ReportRecord(
                requester=context.requester or account,
                request_type=REQUEST_TYPE_OS_ACCOUNT,
                csp="SAC",
                permission="OS계정",
                service=context.service or request.server_group.name,
                content="\n".join([
                    request.server_group.name,
                    request.secret_store.name,
                    request.vault_role_name,
                    account,
                ]),
                period="-",
                note=SAC_OS_ACCOUNT_DESCRIPTION,
            )
            for account in accounts
        ]
        return self.append_records(context, records, "SAC")

    def append_dac_grants(
        self,
        context: ReportContext,
        privilege: DacPrivilege,
        expiry: str,
        users: list[User],
        connections: list[DacConnection],
    ) -> str:
        """DAC DB 권한요청 성공 건을 CSV에 쓴다. OS 계정등록은 SAC 전용이다."""

        today = date.today().isoformat()
        period = f"{today} ~ {expiry}"
        content = "\n\n".join(dac_connection_content(connection) for connection in connections)
        records = [
            ReportRecord(
                requester=context.requester or user.name,
                request_type=REQUEST_TYPE_GRANT,
                csp=dac_csp_label(connections),
                permission=dac_permission_label(privilege),
                service=context.service or dac_service_label(connections),
                content=content,
                period=period,
                note=DAC_GRANT_DESCRIPTION,
            )
            for user in users
        ]
        return self.append_records(context, records, "DAC")

    def append_kac_grants(self, context: ReportContext, role: KacRole, expiry: str, users: list[User]) -> str:
        """KAC role 권한요청 성공 건을 CSV에 쓴다."""

        today = date.today().isoformat()
        period = f"{today} ~ {expiry}"
        content = kac_role_content(role)
        records = [
            ReportRecord(
                requester=context.requester or user.name,
                request_type=REQUEST_TYPE_GRANT,
                csp="KAC",
                permission="Role",
                service=context.service,
                content=content,
                period=period,
                note=KAC_GRANT_DESCRIPTION,
            )
            for user in users
        ]
        return self.append_records(context, records, "KAC")


def read_report_context() -> ReportContext:
    """CSV에 남길 신청 메타데이터를 입력받는다."""

    print("\nCSV 기록 정보 입력")
    print("요청일/처리일/분류/상태는 자동 입력됩니다.")
    defaults = report_context_defaults()
    return ReportContext(
        ticket=read_defaulted("티켓", defaults["ticket"]),
        division=read_defaulted("부문", defaults["division"]),
        team=read_defaulted("부서명", defaults["team"]),
        requester=read_defaulted("접수자(비우면 대상 사용자명 또는 OS계정명)", defaults["requester"]),
        system_name=read_defaulted("접수형태", defaults["system_name"]),
        service=read_defaulted("시스템/서비스명", defaults["service"]),
    )


def report_context_defaults() -> dict[str, str]:
    """CSV 출력 메타데이터 기본값을 만든다.

    로컬 이력 CSV 참조는 권한부여 판단에 쓰지 않고, 이 입력 화면에서
    부문/부서명/접수자/시스템명을 덜 입력하게 하는 용도로만 사용한다.
    """

    defaults = dict(REPORT_DEFAULTS)
    reference = LocalReferenceIndex()
    if not reference.enabled:
        return defaults
    keyword = read_defaulted("CSV 이력 참고 검색값(비우면 건너뜀)", "")
    if not keyword:
        return defaults
    rows = reference.search("report_context", keyword)
    if not rows:
        print(f"[REPORT_REF_NOT_FOUND] {keyword}")
        return defaults
    shown = rows[:10]
    ConsoleView.table(
        ["번호", "부문", "부서명", "접수자", "시스템/서비스명"],
        [
            [
                str(idx),
                item.row.get("division", ""),
                item.row.get("team", ""),
                item.row.get("requester", ""),
                item.row.get("service", ""),
            ]
            for idx, item in enumerate(shown, 1)
        ],
        [4, 12, 24, 18, 32],
    )
    value = read_defaulted("참고 번호", "1")
    numbers = parse_number_selection(value, len(shown))
    if not numbers:
        return defaults
    selected = shown[numbers[0] - 1].row
    for key in ("ticket", "division", "team", "requester", "system_name", "service"):
        if selected.get(key):
            defaults[key] = selected[key]
    return defaults


def dac_permission_label(privilege: DacPrivilege) -> str:
    name = privilege.name.lower()
    if "dba" in name:
        return "DBA"
    if "rw" in name or "write" in name:
        return "RW"
    if "ro" in name or "read" in name:
        return "RO"
    return privilege.name


def dac_csp_label(connections: list[DacConnection]) -> str:
    values: list[str] = []
    for connection in connections:
        value = (connection.cloud_provider_type or "").upper()
        if value and value != "NONE" and value not in values:
            values.append(value)
    return "/".join(values) if values else "DAC"


def dac_service_label(connections: list[DacConnection]) -> str:
    if not connections:
        return ""
    if len(connections) == 1:
        return connections[0].name
    return f"{connections[0].name} 외 {len(connections) - 1}건"


def dac_connection_content(connection: DacConnection) -> str:
    lines = [connection.name]
    lines.extend(item for item in (connection.endpoints or []) if item)
    return "\n".join(lines)


def kac_role_content(role: KacRole) -> str:
    lines = [role.name]
    policies = role.policies or []
    if policies:
        lines.append("policies: " + ", ".join(policies))
    return "\n".join(lines)
