from __future__ import annotations

import sys

from .acl import AclTool
from .api import ApiClient
from .commands import CommandDispatcher, FunctionCommand
from .config import IDLE_TIMEOUT_MINUTES, RuntimeConfig, load_runtime_config
from .dac import DacTool
from .io_utils import get_initial_token, prompt_token, read_shell_command
from .kac import KacTool
from .menus import DacMenu, KacMenu, SacMenu
from .models import Quit
from .os_account import OsAccountTool
from .resolver import Resolver, SacRoleCache
from .tag_lookup import TagLookupTool
from .view import ConsoleView


class ExitRequested(Exception):
    pass


def parse_runtime_flags(argv: list[str]) -> bool | None:
    """기존 실행 옵션을 호환용으로만 해석한다.

    DAC IP/endpoint 검색은 항상 기본 동작입니다.
    -fullscan은 SAC role cache를 처음부터 켜는 호환 옵션으로만 남깁니다.
    """

    use_sac_role_cache: bool | None = None
    for arg in argv:
        value = arg.lower()
        if value == "-fullscan":
            use_sac_role_cache = True
        else:
            print(f"[INFO] 알 수 없는 옵션은 무시합니다: {arg}")
    return use_sac_role_cache


def create_valid_client(runtime: RuntimeConfig) -> ApiClient:
    token = get_initial_token()
    while True:
        client = ApiClient(runtime.base_url, token, insecure_ssl=runtime.insecure_ssl)
        try:
            client.validate_token()
            return client
        except Exception as exc:
            print(f"[TOKEN ERROR] {exc}")
            token = prompt_token("새 API Token 입력: ")


def print_startup(runtime: RuntimeConfig, dispatcher: CommandDispatcher):
    print("\nAccess Control SAC/DAC/KAC Tool")
    ConsoleView.table(
        ["설정", "값"],
        [
            ["환경", runtime.env_name],
            ["base_url", runtime.base_url],
            ["CSV 환경", runtime.csv_env],
            ["CSV 파일", runtime.report_file or "주차별 자동 파일"],
            ["CSV 단위", runtime.report_period],
            [
                "참조 CSV",
                "object {0} / tag {1}".format(
                    "ON" if runtime.use_local_object_reference_csv else "OFF",
                    "ON" if runtime.use_local_tag_reference_csv else "OFF",
                ),
            ],
        ],
        [12, 72],
    )
    ConsoleView.table(["분류", "명령", "축약", "설명"], dispatcher.rows(), [8, 12, 8, 54])
    print("입력 제어: /b = 이전 메뉴, /q = 종료")


def main():
    use_sac_role_cache = parse_runtime_flags(sys.argv[1:])

    # 1. 코드 설정을 읽고 API 토큰을 검증한다.
    runtime = load_runtime_config(use_sac_role_cache=use_sac_role_cache)
    client = create_valid_client(runtime)

    # 2. 업무별 Tool 객체를 만든다. Tool은 실제 업무 흐름을 담당한다.
    sac_role_cache = SacRoleCache()
    tag_lookup_tool = TagLookupTool(client, runtime)
    acl_tool = AclTool(client, runtime, sac_role_cache, tag_lookup_tool)
    os_account_tool = OsAccountTool(client, runtime)
    dac_tool = DacTool(client, runtime, Resolver(client, sac_role_cache, tag_lookup_tool), tag_lookup_tool)
    kac_tool = KacTool(client, runtime, Resolver(client, sac_role_cache, tag_lookup_tool), tag_lookup_tool)
    sac_menu = SacMenu(runtime, acl_tool, os_account_tool, tag_lookup_tool)
    dac_menu = DacMenu(dac_tool, tag_lookup_tool)
    kac_menu = KacMenu(kac_tool, tag_lookup_tool)

    # 3. 큰 분류는 SAC/DAC/KAC로 유지한다. 세부 작업은 각 메뉴 안에서 고른다.
    dispatcher = CommandDispatcher([
        FunctionCommand("sac", ("s",), "서버 접근 권한/OS계정/태그 조회", sac_menu.run, "SAC", alias_label="s"),
        FunctionCommand("dac", ("d",), "DB 객체 권한/태그 조회", dac_menu.run, "DAC", alias_label="d"),
        FunctionCommand("kac", ("k",), "Kubernetes role 권한/태그 조회", kac_menu.run, "KAC", alias_label="k"),
        FunctionCommand("exit", ("e", "q", "/q", "quit"), "종료", lambda: (_ for _ in ()).throw(ExitRequested()), "공통", alias_label="e/q"),
        FunctionCommand("grant", ("g",), "SAC role 부여", lambda: sac_menu.run("grant"), "SAC", visible=False),
        FunctionCommand("revoke", ("r",), "SAC role 회수", lambda: sac_menu.run("revoke"), "SAC", visible=False),
        FunctionCommand("os", ("o",), "SAC 서버 OS 계정 등록", lambda: sac_menu.run("os"), "SAC", visible=False),
    ])
    print_startup(runtime, dispatcher)

    while True:
        raw = read_shell_command("qpa> ")
        if raw is None:
            print(f"{IDLE_TIMEOUT_MINUTES}분 동안 입력이 없어 종료합니다.")
            break
        if not raw.strip():
            continue
        try:
            if not dispatcher.dispatch(raw):
                print("사용 가능 명령: sac/s, dac/d, kac/k, exit/e")
        except ExitRequested:
            break
        except Quit:
            break
        except KeyboardInterrupt:
            print("\n중단했습니다.")
        except Exception as exc:
            print(f"[ERROR] {exc}")
