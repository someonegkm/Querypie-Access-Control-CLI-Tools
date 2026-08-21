from __future__ import annotations

from .io_utils import read_value
from .models import Back
from .view import ConsoleView


class SacMenu:
    """SAC 안의 role grant/revoke, OS 계정등록, 태그 기반 조회를 묶는 메뉴."""

    def __init__(self, runtime, acl_tool, os_account_tool, tag_lookup_tool):
        self.runtime = runtime
        self.acl_tool = acl_tool
        self.os_account_tool = os_account_tool
        self.tag_lookup_tool = tag_lookup_tool

    def run(self, action: str = ""):
        if action:
            self.dispatch(action)
            return
        while True:
            self.print_menu()
            try:
                value = read_value("sac 작업 [grant/revoke/os/lookup/cache, 기본 grant, /b=상위]: ", allow_empty=True)
            except Back:
                return
            action = value or "grant"
            if self.dispatch(action):
                continue

    def dispatch(self, action: str) -> bool:
        value = action.lower()
        try:
            if value in ("grant", "g", "권한부여", "부여"):
                self.acl_tool.grant()
                return True
            if value in ("revoke", "r", "회수"):
                self.acl_tool.revoke()
                return True
            if value in ("os", "o", "os계정", "계정"):
                self.os_account_tool.run()
                return True
            if value in ("lookup", "l", "tag", "t", "조회"):
                self.tag_lookup_tool.run_scope("sac")
                return True
            if value in ("cache", "c"):
                self.toggle_sac_role_cache()
                return True
            print("SAC 작업은 grant, revoke, os, lookup, cache 중 하나를 입력하세요.")
            return False
        except Back:
            print("SAC 메뉴로 돌아갑니다.")
            return True

    def toggle_sac_role_cache(self):
        self.runtime.use_sac_role_cache = not self.runtime.use_sac_role_cache
        if self.runtime.use_sac_role_cache:
            self.acl_tool.ensure_sac_role_cache()
        print(f"[SAC CACHE] {'ON' if self.runtime.use_sac_role_cache else 'OFF'}")

    def print_menu(self):
        ConsoleView.table(
            ["SAC 작업", "입력", "설명"],
            [
                ["role 부여", "grant/g", "서버 접근 role 부여 또는 만료일 갱신"],
                ["role 회수", "revoke/r", "사용자의 현재 role 중 선택 회수"],
                ["OS 계정등록", "os/o", "SAC 서버그룹 OS 계정 등록"],
                ["태그 조회", "lookup/l", "서버그룹 태그와 role 검색 힌트 조회"],
                ["SAC role cache", "cache/c", f"현재 {'ON' if self.runtime.use_sac_role_cache else 'OFF'}"],
            ],
            [14, 12, 54],
        )


class DacMenu:
    """DAC 안의 DB 객체 권한부여와 태그 기반 조회를 묶는 메뉴."""

    def __init__(self, dac_tool, tag_lookup_tool):
        self.dac_tool = dac_tool
        self.tag_lookup_tool = tag_lookup_tool

    def run(self, action: str = ""):
        if action:
            self.dispatch(action)
            return
        while True:
            self.print_menu()
            try:
                value = read_value("dac 작업 [grant/revoke/lookup, 기본 grant, /b=상위]: ", allow_empty=True)
            except Back:
                return
            action = value or "grant"
            if self.dispatch(action):
                continue

    def dispatch(self, action: str) -> bool:
        value = action.lower()
        try:
            if value in ("grant", "g", "권한부여", "부여"):
                self.dac_tool.run("grant")
                return True
            if value in ("revoke", "r", "회수"):
                self.dac_tool.run("revoke")
                return True
            if value in ("lookup", "l", "tag", "t", "조회"):
                self.tag_lookup_tool.run_scope("dac")
                return True
            print("DAC 작업은 grant, revoke, lookup 중 하나를 입력하세요.")
            return False
        except Back:
            print("DAC 메뉴로 돌아갑니다.")
            return True

    @staticmethod
    def print_menu():
        ConsoleView.table(
            ["DAC 작업", "입력", "설명"],
            [
                ["DB 권한부여", "grant/g", "DB 객체를 먼저 고르고 privilege/기간/사용자 공통 적용"],
                ["DB 권한회수", "revoke/r", "사용자의 현재 DB 권한 중 선택 회수"],
                ["태그 조회", "lookup/l", "DB connection 태그 기준 후보 조회"],
            ],
            [14, 12, 58],
        )


class KacMenu:
    """KAC 안의 role 권한부여/회수와 태그 기반 조회를 묶는 메뉴."""

    def __init__(self, kac_tool, tag_lookup_tool):
        self.kac_tool = kac_tool
        self.tag_lookup_tool = tag_lookup_tool

    def run(self, action: str = ""):
        if action:
            self.dispatch(action)
            return
        while True:
            self.print_menu()
            try:
                value = read_value("kac 작업 [grant/revoke/lookup, 기본 grant, /b=상위]: ", allow_empty=True)
            except Back:
                return
            action = value or "grant"
            if self.dispatch(action):
                continue

    def dispatch(self, action: str) -> bool:
        value = action.lower()
        try:
            if value in ("grant", "g", "권한부여", "부여"):
                self.kac_tool.run("grant")
                return True
            if value in ("revoke", "r", "회수"):
                self.kac_tool.run("revoke")
                return True
            if value in ("lookup", "l", "tag", "t", "조회"):
                self.tag_lookup_tool.run_scope("kac")
                return True
            print("KAC 작업은 grant, revoke, lookup 중 하나를 입력하세요.")
            return False
        except Back:
            print("KAC 메뉴로 돌아갑니다.")
            return True

    @staticmethod
    def print_menu():
        ConsoleView.table(
            ["KAC 작업", "입력", "설명"],
            [
                ["role 부여", "grant/g", "Kubernetes role 부여 또는 갱신"],
                ["role 회수", "revoke/r", "사용자의 현재 KAC role 중 선택 회수"],
                ["태그 조회", "lookup/l", "KAC cluster 태그 기준 후보 조회"],
            ],
            [14, 12, 54],
        )
