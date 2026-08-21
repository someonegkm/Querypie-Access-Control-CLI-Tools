from __future__ import annotations

import unicodedata

from .models import Role, User
from .sac_role_utils import role_resource_key, role_warning_label, parse_role_name


def display_width(text: str) -> int:
    width = 0
    for char in str(text or ""):
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("F", "W") else 1
    return width


def trim(text: str, width: int) -> str:
    text = str(text or "-")
    if display_width(text) <= width:
        return text
    result = ""
    for char in text:
        if display_width(result + char + "...") > width:
            break
        result += char
    return result + "..."


def pad(text: str, width: int) -> str:
    text = trim(text, width)
    return text + " " * max(width - display_width(text), 0)


def print_table(headers: list[str], rows: list[list[str]], widths: list[int]):
    def line(values: list[str]) -> str:
        return "| " + " | ".join(pad(v, w) for v, w in zip(values, widths)) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print("  " + sep)
    print("  " + line(headers))
    print("  " + sep)
    for row in rows:
        print("  " + line(row))
    print("  " + sep)


def auto_widths(
    headers: list[str],
    rows: list[list[str]],
    min_widths: list[int] | None = None,
    max_widths: list[int] | None = None,
) -> list[int]:
    widths: list[int] = []
    for idx, header in enumerate(headers):
        values = [str(row[idx]) for row in rows if idx < len(row)]
        raw_width = max([display_width(header)] + [display_width(value) for value in values])
        if min_widths and idx < len(min_widths):
            raw_width = max(raw_width, min_widths[idx])
        if max_widths and idx < len(max_widths):
            raw_width = min(raw_width, max_widths[idx])
        widths.append(raw_width)
    return widths


class ConsoleView:
    @staticmethod
    def user_contact(user: User) -> str:
        return user.email or user.login_id or "-"

    @staticmethod
    def table(headers: list[str], rows: list[list[str]], widths: list[int]):
        print_table(headers, rows, widths)

    @staticmethod
    def auto_table(
        headers: list[str],
        rows: list[list[str]],
        min_widths: list[int] | None = None,
        max_widths: list[int] | None = None,
    ):
        print_table(headers, rows, auto_widths(headers, rows, min_widths, max_widths))

    @staticmethod
    def role_candidates(roles: list[Role]):
        rows = []
        for idx, role in enumerate(roles, 1):
            info = parse_role_name(role.name)
            rows.append([str(idx), role_resource_key(role), role_warning_label(role), info.role_type, role.name])
        ConsoleView.auto_table(
            ["번호", "vpc/project", "주의", "type", "role"],
            rows,
            [4, 18, 4, 8, 34],
            [4, 34, 6, 10, 84],
        )

    @staticmethod
    def user_resolution(keyword: str, user: User):
        print("\n  사용자 확인 결과")
        print_table(
            ["입력값", "사용자", "email/loginId"],
            [[keyword, user.name, ConsoleView.user_contact(user)]],
            [12, 18, 32],
        )

    @staticmethod
    def user_candidates(keyword: str, users: list[User]):
        print(f"\n  {keyword}: 후보 {len(users)}명")
        rows = [[str(idx), user.name, user.login_id, user.email] for idx, user in enumerate(users, 1)]
        ConsoleView.auto_table(["번호", "사용자", "loginId", "email"], rows, [4, 12, 14, 24], [4, 24, 28, 48])

    @staticmethod
    def selected_users(users: list[User]):
        print_table(
            ["선택", "사용자", "email/loginId"],
            [["대상", user.name, ConsoleView.user_contact(user)] for user in users],
            [6, 18, 32],
        )

    @staticmethod
    def users(title: str, users: list[User]):
        if users:
            print(f"\n{title}")
            ConsoleView.auto_table(
                ["사용자", "email/loginId"],
                [[user.name, ConsoleView.user_contact(user)] for user in users],
                [12, 24],
                [24, 40],
            )
