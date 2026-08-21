# Access Control API CLI

Python 3.11 표준 라이브러리만으로 만든 권한 관리 CLI 포트폴리오 샘플입니다.

이 저장소는 실제 운영 저장소에서 민감할 수 있는 고객사명, 개인 로컬 경로, 운영 환경명, 도메인, 토큰, 리포트 CSV, 백업 파일, Git 이력을 제거한 공개용 버전입니다.

## 주요 기능

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

Windows 실행 스크립트도 포함되어 있습니다.

```powershell
.\run_acl_cli.cmd
```

## 설정

실행 전 [acl_tool/config.py](acl_tool/config.py)에서 샘플 URL과 도메인을 실제 테스트 환경에 맞게 바꿉니다.

```python
ACTIVE_ENV = "demo"
ENVIRONMENTS = {
    "demo": {
        "base_url": "https://acl-platform.example.com",
    },
}
```

API 토큰은 실행 중 입력만 받고 파일에 저장하지 않습니다.

## 문서

| 문서 | 내용 |
|---|---|
| [01_USAGE.md](docs/01_USAGE.md) | 실행, 설정, 메뉴, CSV 기록, 리퍼런스 CSV |
| [02_LOGIC.md](docs/02_LOGIC.md) | 처리 흐름, 후보 선택, 모듈 구조, 확장 기준 |
| [03_API.md](docs/03_API.md) | API 호출 순서, 검증 전략, scan/cache 비용 |

## 공개본 정리 기준

| 기준 | 처리 |
|---|---|
| 비밀값 | 토큰, 키, CSV, 백업 파일은 포함하지 않음 |
| 환경 정보 | 운영/고객사 환경명 대신 `demo`만 유지 |
| 도메인 | `example.com` 계열 샘플 도메인으로 치환 |
| 로컬 경로 | 개인 PC 경로 제거 |
| 이력 | 원본 Git history 없이 새 저장소로 초기화 |
