from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .config import AUTH_HEADER_NAME, AUTH_HEADER_PREFIX
from .io_utils import prompt_token


class ApiClient:
    def __init__(self, base_url: str, token: str, insecure_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.context = ssl._create_unverified_context() if insecure_ssl else None

    def reset_token(self):
        self.token = prompt_token("새 API Token 입력: ")

    def validate_token(self):
        self.request("GET", "/api/external/v3/iam/me")
        print("[TOKEN OK] 토큰 유효성 확인 완료")

    def request(self, method: str, path: str, body=None, params: dict | None = None, retry: bool = True):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        url = self.base_url + path
        if params:
            query = urllib.parse.urlencode({key: value for key, value in params.items() if value is not None})
            url += ("&" if "?" in url else "?") + query
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                AUTH_HEADER_NAME: AUTH_HEADER_PREFIX + self.token,
            },
        )
        while True:
            try:
                with urllib.request.urlopen(req, timeout=30, context=self.context) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                body_text = e.read().decode("utf-8", errors="replace")
                if is_token_error(e.code, body_text) and retry:
                    print(f"\n[TOKEN_RETRY] 인증 실패 또는 토큰 만료로 보입니다: {method} {path}")
                    self.reset_token()
                    req.add_header(AUTH_HEADER_NAME, AUTH_HEADER_PREFIX + self.token)
                    print("[TOKEN_RETRY] 새 토큰으로 같은 요청을 다시 시도합니다.")
                    continue
                raise RuntimeError(f"HTTP {e.code}: {body_text}") from e
            except urllib.error.URLError as e:
                raise RuntimeError(
                    f"URL Error: {e}. If this is a self-signed certificate test environment, "
                    "set INSECURE_SSL = True in acl_tool/config.py."
                ) from e


def is_token_error(status_code: int, body_text: str) -> bool:
    if status_code == 401:
        return True
    try:
        data = json.loads(body_text)
        error = data.get("error", {})
        code = str(error.get("code", ""))
        message = str(error.get("message", "")).lower()
        return code in ("QPS-10014", "QPS-10002") or "token" in message
    except Exception:
        return "token" in body_text.lower()
