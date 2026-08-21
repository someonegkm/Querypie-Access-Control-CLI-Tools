from __future__ import annotations

import re
import urllib.parse
from datetime import date, timedelta


def quote(value: str) -> str:
    return urllib.parse.quote(value.strip())


def unique(values: list[str]) -> list[str]:
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


FULL_SEARCH_TERMS = {"all", "full", "fullscan", "*", "전체"}


def normalize_search_key(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def is_full_search(value: str) -> bool:
    return normalize_search_key(value) in FULL_SEARCH_TERMS


def inclusive_expiry_date(days: int) -> str:
    """Return the date that ends an inclusive N-day permission period."""

    return (date.today() + timedelta(days=days - 1)).isoformat()


def end_of_day_utc(expiry: str) -> str:
    return f"{expiry}T23:59:59Z"


def page_numbers(max_pages: int):
    """API 페이지 조회에 사용할 페이지 번호를 만듭니다.

    max_pages가 0이면 API가 빈 목록, 마지막 페이지, 페이지 크기 미만
    결과를 줄 때까지 계속 조회합니다.
    """

    page = 0
    while max_pages <= 0 or page < max_pages:
        yield page
        page += 1


def warn_scan_limit(label: str, max_pages: int, page_size: int):
    if max_pages <= 0:
        return
    approx = max_pages * page_size
    print(
        f"[SCAN_LIMIT] {label}: 최대 {max_pages}페이지({approx}건 기준)에 도달했습니다. "
        "결과가 누락될 수 있습니다. config.py에서 최대 페이지를 늘리거나 0으로 설정하면 API가 끝날 때까지 조회합니다."
    )


def first(obj: dict, *keys: str) -> str:
    for key in keys:
        value = obj.get(key)
        if value is not None:
            return str(value)
    return ""


def response_list(data) -> list[dict]:
    if data is None:
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("items", "list", "users", "roles", "data", "delegate"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        for key in ("user", "foundUser"):
            value = data.get(key)
            if isinstance(value, dict):
                return [value]
        if any(key in data for key in ("uuid", "userUuid", "serverRoleUuid")):
            return [data]
    return []


def parse_number_selection(value: str, max_number: int) -> list[int] | None:
    value = value.strip().lower()
    if value in ("a", "all", "전체"):
        return list(range(1, max_number + 1))
    parts = [part for part in re.split(r"[,\s]+", value) if part]
    if not parts:
        return None
    numbers: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        number = int(part)
        if number < 1 or number > max_number:
            return None
        if number not in numbers:
            numbers.append(number)
    return numbers
