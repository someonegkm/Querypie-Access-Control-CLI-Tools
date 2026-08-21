from __future__ import annotations

import csv
import glob
import os
import sys




DEFAULT_INPUT_PATTERNS = ("reports/*.csv",)
OUTPUT_FILE = "reference/report_context.csv"
OUTPUT_HEADERS = [
    "ticket",
    "division",
    "team",
    "requester",
    "system_name",
    "service",
    "keyword",
    "source_file",
]


def main(argv: list[str]) -> int:
    paths = resolve_input_paths(argv) if argv else resolve_default_inputs()
    if not paths:
        print("[REPORT_REF] \uc77d\uc744 CSV\uac00 \uc5c6\uc2b5\ub2c8\ub2e4. reports \ud3f4\ub354\uc5d0 \uc774\ub825 CSV\ub97c \ub450\uac70\ub098 \ud30c\uc77c/\ud3f4\ub354 \uacbd\ub85c\ub97c \uc778\uc790\ub85c \ub123\uc73c\uc138\uc694.")
        return 1
    rows = []
    for path in paths:
        rows.extend(read_report_rows(path))
    rows = dedupe_rows(rows)
    write_rows(OUTPUT_FILE, rows)
    print(f"[REPORT_REF] \uc785\ub825 \ud30c\uc77c {len(paths)}\uac1c")
    print(f"[REPORT_REF] \uc0c9\uc778 \ud589 {len(rows)}\uac1c")
    print(f"[REPORT_REF] \ucd9c\ub825: {OUTPUT_FILE}")
    return 0


def resolve_default_inputs() -> list[str]:
    paths: list[str] = []
    for pattern in DEFAULT_INPUT_PATTERNS:
        paths.extend(glob.glob(pattern))
    return sorted(unique(paths))


def resolve_input_paths(values: list[str]) -> list[str]:
    paths: list[str] = []
    for value in values:
        if os.path.isdir(value):
            paths.extend(glob.glob(os.path.join(value, "*.csv")))
        elif os.path.isfile(value):
            paths.append(value)
        else:
            paths.extend(glob.glob(value))
    return sorted(unique(paths))


def read_report_rows(path: str) -> list[dict[str, str]]:
    result = []
    with open_csv_with_fallback(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            normalized = normalize_row(row)
            item = {
                "ticket": pick(normalized, "\ud2f0\ucf13", "ticket"),
                "division": pick(normalized, "\ubd80\ubb38", "division"),
                "team": pick(normalized, "\ubd80\uc11c\uba85", "team", "department"),
                "requester": pick(normalized, "\uc811\uc218\uc790", "requester"),
                "system_name": pick(normalized, "\uc811\uc218\ud615\ud0dc", "system_name"),
                "service": pick(normalized, "\uc2dc\uc2a4\ud15c/\uc11c\ube44\uc2a4\uba85", "service"),
                "source_file": path,
            }
            item["keyword"] = " ".join(value for value in item.values() if value)
            if item["team"] or item["requester"] or item["service"]:
                result.append(item)
    return result


def open_csv_with_fallback(path: str):
    for encoding in ("utf-8-sig", "cp949"):
        try:
            f = open(path, "r", encoding=encoding, newline="")
            f.read()
            f.seek(0)
            return f
        except UnicodeDecodeError:
            try:
                f.close()
            except Exception:
                pass
    return open(path, "r", encoding="utf-8-sig", errors="replace", newline="")


def normalize_row(row: dict[str, str]) -> dict[str, str]:
    return {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}


def pick(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        if row.get(key):
            return row[key]
    return ""


def dedupe_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    found: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for row in rows:
        key = (row["division"], row["team"], row["requester"], row["service"])
        if key not in found:
            found[key] = row
    return list(found.values())


def unique(values: list[str]) -> list[str]:
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def write_rows(path: str, rows: list[dict[str, str]]):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in OUTPUT_HEADERS})


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
