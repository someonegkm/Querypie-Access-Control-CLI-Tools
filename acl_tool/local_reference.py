from __future__ import annotations

import csv
import os
from dataclasses import dataclass

from .config import LOCAL_REFERENCE_DIR, LOCAL_REFERENCE_FILES, USE_LOCAL_REFERENCE_CSV


@dataclass
class LocalReferenceRow:
    source: str
    row: dict[str, str]


class LocalReferenceIndex:
    """CSV 보고서 입력 기본값을 찾기 위한 선택형 CSV 인덱스입니다.

    기본은 OFF입니다. ON이면 성공 작업 뒤 CSV 기록 입력 화면에서 부문,
    부서명, 접수자, 시스템/서비스명 반복 입력을 줄이는 용도로만 사용합니다.
    사용자, role, DB, KAC role, 태그 lookup 결과를 결정하는 데는 쓰지 않습니다.
    """

    def __init__(self, enabled: bool | None = None):
        self.enabled = USE_LOCAL_REFERENCE_CSV if enabled is None else enabled
        self.cache: dict[str, list[LocalReferenceRow]] = {}

    def search(self, reference_name: str, keyword: str) -> list[LocalReferenceRow]:
        if not self.enabled:
            return []
        rows = self.load(reference_name)
        needle = keyword.lower()
        return [
            item
            for item in rows
            if needle in " ".join(item.row.values()).lower()
        ]

    def load(self, reference_name: str) -> list[LocalReferenceRow]:
        if reference_name in self.cache:
            return self.cache[reference_name]
        configured = LOCAL_REFERENCE_FILES.get(reference_name, "")
        if not configured:
            self.cache[reference_name] = []
            return []
        path = configured if os.path.isabs(configured) else os.path.join(LOCAL_REFERENCE_DIR, configured)
        if not os.path.exists(path):
            self.cache[reference_name] = []
            return []
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            rows = [LocalReferenceRow(reference_name, normalize_row(row)) for row in reader]
        self.cache[reference_name] = rows
        return rows


def normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}
