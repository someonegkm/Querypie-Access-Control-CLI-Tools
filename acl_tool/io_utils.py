from __future__ import annotations

import sys
import time
import unicodedata
from getpass import getpass

from .config import IDLE_TIMEOUT_MINUTES
from .models import Back, Quit

if sys.platform == "win32":
    import msvcrt
else:
    msvcrt = None


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip("\"'")
    for char in ("\ufeff", "\u200b", "\u200c", "\u200d"):
        token = token.replace(char, "")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    # VDI/원격 붙여넣기는 \x16 같은 숨은 제어문자를 섞을 수 있습니다.
    # HTTP header에는 이런 문자를 넣을 수 없으므로 사용 전에 제거합니다.
    return "".join(
        char
        for char in token
        if not char.isspace() and unicodedata.category(char)[0] != "C"
    )


def token_preview(token: str) -> str:
    return f"length={len(token or '')}"


def read_hidden_windows(prompt: str) -> str:
    print(prompt, end="", flush=True)
    chars: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            print()
            return "".join(chars)
        if ch == "\003":
            raise KeyboardInterrupt
        if ch == "\b":
            if chars:
                chars.pop()
            continue
        if ch in ("\x00", "\xe0"):
            try:
                msvcrt.getwch()
            except Exception:
                pass
            continue
        chars.append(ch)


def prompt_token(prompt: str = "API Token 입력: ") -> str:
    while True:
        if sys.platform == "win32":
            raw = read_hidden_windows(prompt)
        else:
            raw = getpass(prompt)
        token = normalize_token(raw)
        print(f"[TOKEN INPUT] {token_preview(token)}")
        if token.lower() in ("/q", "exit", "quit"):
            raise Quit
        if token:
            return token
        print("토큰이 비어 있습니다. 종료하려면 /q를 입력하세요.")


def get_initial_token() -> str:
    return prompt_token()


def read_value(prompt: str, allow_empty: bool = False) -> str:
    while True:
        value = input(prompt).strip()
        lower = value.lower()
        if lower in ("/b", "back"):
            raise Back
        if lower in ("/q", "exit", "quit"):
            raise Quit
        if value or allow_empty:
            return value
        print("값을 입력하세요. 이전 단계: /b, 종료: /q")


def run_input_steps(steps: list, state: dict | None = None) -> dict:
    state = {} if state is None else state
    index = 0
    while index < len(steps):
        try:
            steps[index](state)
            index += 1
        except Back:
            if index == 0:
                raise
            index -= 1
            print("이전 입력 단계로 돌아갑니다.")
    return state


def read_defaulted(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = read_value(f"{label}{suffix}: ", allow_empty=True)
    return value or default


def read_role_keyword(prompt: str, preview_func=None) -> str:
    if sys.platform != "win32":
        return read_value(prompt)

    print(prompt, end="", flush=True)
    chars: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            print()
            value = "".join(chars).strip()
            lower = value.lower()
            if lower in ("/b", "back"):
                raise Back
            if lower in ("/q", "exit", "quit"):
                raise Quit
            if value:
                return value
            print("값을 입력하세요. 이전 단계: /b, 종료: /q")
            print(prompt, end="", flush=True)
            chars.clear()
            continue
        if ch == "\003":
            raise KeyboardInterrupt
        if ch == "\t":
            value = "".join(chars).strip()
            print()
            preview_func(value) if preview_func else print("[ROLE CACHE] 후보보기 없음")
            print(prompt + "".join(chars), end="", flush=True)
            continue
        if ch == "\b":
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        if ch in ("\x00", "\xe0"):
            try:
                msvcrt.getwch()
            except Exception:
                pass
            continue
        chars.append(ch)
        sys.stdout.write(ch)
        sys.stdout.flush()


def read_shell_command(prompt: str) -> str | None:
    if sys.platform != "win32":
        try:
            return input(prompt)
        except EOFError:
            return None

    print(prompt, end="", flush=True)
    start = time.time()
    timeout = IDLE_TIMEOUT_MINUTES * 60
    chars: list[str] = []
    while True:
        if time.time() - start >= timeout:
            print()
            return None
        if msvcrt.kbhit():
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                print()
                return "".join(chars)
            if ch == "\003":
                raise KeyboardInterrupt
            if ch == "\b":
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            chars.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
        time.sleep(0.05)


def read_user_inputs() -> list[str]:
    print("\n사용자 이름 일부, loginId 또는 email을 입력하세요.")
    print("쉼표(,) 또는 줄바꿈으로 여러 명 입력 가능.")
    print("빈 줄이면 입력 종료. 이전 단계: /b, 종료: /q")
    values: list[str] = []
    while True:
        value = read_value("> ", allow_empty=True)
        if not value:
            break
        values.extend(part.strip() for part in value.split(",") if part.strip())
    return values


def read_csv_items(value: str) -> list[str]:
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]
