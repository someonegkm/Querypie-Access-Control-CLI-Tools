# Access Control API CLI

SAC/DAC/KAC 권한 업무를 처리하는 Python 3.11 CLI입니다.
외부 패키지 없이 표준 라이브러리만 사용합니다.

## 기능

| 영역 | 기능 |
|---|---|
| SAC | 서버 접근 role 부여/회수, OS 계정 등록, 태그 기반 후보 조회 |
| DAC | DB 권한 부여/회수, DB명/endpoint/IP/태그 기반 후보 조회 |
| KAC | Kubernetes role 부여/회수, policy/description/태그 기반 후보 조회 |
| 공통 | API 사전 검증, 변경 후 검증, 실행 중 cache, CSV 이력 기록 |

## 실행

```powershell
py .\acl_cli.py
```

Windows 실행 스크립트:

```powershell
.\run_acl_cli.cmd
```

## 설정

실행 환경은 [acl_tool/config.py](acl_tool/config.py)에서 관리합니다.

```python
ACTIVE_ENV = "demo"
ENVIRONMENTS = {
    "demo": {
        "base_url": "https://acl-platform.example.com",
    },
}
```

API 토큰은 실행 중 입력받고 파일에 저장하지 않습니다.

## 문서

| 문서 | 내용 |
|---|---|
| [01_USAGE.md](docs/01_USAGE.md) | 실행, 설정, 메뉴, CSV 기록, 리퍼런스 CSV |
| [02_LOGIC.md](docs/02_LOGIC.md) | 처리 흐름, 후보 선택, 모듈 구조, 확장 기준 |
| [03_API.md](docs/03_API.md) | API 호출 순서, 검증 전략, scan/cache 비용 |
