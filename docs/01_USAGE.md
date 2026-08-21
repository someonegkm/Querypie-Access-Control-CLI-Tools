# 사용법

## 실행

```powershell
py .\acl_cli.py
```

또는 Windows 실행 스크립트를 사용합니다.

```powershell
.\run_acl_cli.cmd
```

## 설정

설정은 [acl_tool/config.py](../acl_tool/config.py)에서 바꿉니다.

| 설정 | 기본값 | 설명 |
|---|---:|---|
| `ACTIVE_ENV` | `demo` | API 접속 환경. CSV 환경 값도 이 값을 따릅니다. |
| `ENVIRONMENTS.demo.base_url` | 샘플 URL | 실제 테스트 API base URL로 교체합니다. |
| `INSECURE_SSL` | `False` | 자체 서명 인증서 테스트 환경에서만 `True`로 변경합니다. |
| `USE_SAC_ROLE_CACHE` | `False` | SAC role 전체 목록을 메모리에 올려 후보 검색에 재사용합니다. |
| `USE_LOCAL_REFERENCE_CSV` | `False` | CSV 기록 입력 기본값을 기존 이력에서 찾습니다. |
| `USE_LOCAL_OBJECT_REFERENCE_CSV` | `False` | SAC role, DAC DB, KAC role 후보를 로컬 CSV에서 먼저 찾습니다. |
| `USE_LOCAL_TAG_REFERENCE_CSV` | `False` | SAC/DAC/KAC 태그 lookup 후보를 로컬 CSV에서 먼저 찾습니다. |
| `REPORT_PERIOD` | `week` | CSV 기록 파일을 주차 단위로 만듭니다. |
| `REPORT_FILE` | 빈 값 | 비우면 주차별 자동 파일, 값을 넣으면 해당 파일에 계속 누적합니다. |

## 메뉴

처음 화면은 큰 분류만 고릅니다.

| 입력 | 영역 | 설명 |
|---|---|---|
| `sac`, `s` | SAC | 서버 접근 role 부여/회수, OS 계정 등록, 태그 조회 |
| `dac`, `d` | DAC | DB 권한 부여/회수, 태그 조회 |
| `kac`, `k` | KAC | Kubernetes role 부여/회수, 태그 조회 |
| `exit`, `e`, `q` | 종료 | 프로그램 종료 |

각 영역 안에서 다시 작업을 고릅니다.

| 영역 | 작업 |
|---|---|
| SAC | `grant/g`, `revoke/r`, `os/o`, `lookup/l`, `cache/c` |
| DAC | `grant/g`, `revoke/r`, `lookup/l` |
| KAC | `grant/g`, `revoke/r`, `lookup/l` |

입력 중 `/b`는 직전 입력 단계로 돌아가고, `/q`는 종료입니다.
후보 표에서 `all`, `full`, `fullscan`, `*` 또는 `전체`를 검색어로 입력하면 명시적 전체 cache 검색을 실행합니다.

## CSV 기록

권한 부여나 OS 계정 등록이 API 검증까지 성공하면 CSV 기록을 남깁니다.
기본값은 SAC/DAC/KAC별 주차 파일입니다.

```text
reports/AccessPlatform_SAC_Access_Report_YYYY-Www.csv
reports/AccessPlatform_DAC_Access_Report_YYYY-Www.csv
reports/AccessPlatform_KAC_Access_Report_YYYY-Www.csv
```

자동 입력:

| 컬럼 | 값 |
|---|---|
| 요청일 | 실행 당일 |
| 처리일 | 실행 당일 |
| 환경 | `ACTIVE_ENV` |
| 상태 | `완료` |

## 리퍼런스 CSV

로컬 CSV는 반복 입력과 API scan 비용을 줄이기 위한 read-only 인덱스입니다.
CSV에 있는 값도 실제 변경 전 API와 다시 대조합니다.

| 파일 | 용도 |
|---|---|
| `reference/report_context.csv` | 리포트 입력 기본값 |
| `reference/sac_roles.csv` | SAC role 후보 |
| `cluster_groups.csv`, `clusters.csv` | DAC DB/cluster 후보 |
| `reference/kac_roles.csv` | KAC role 후보 |
| `reference/*_tags.csv` | 태그 lookup 후보 |

## 수동 테스트

1. 샘플 URL을 테스트 API로 바꾼 뒤 토큰 입력 화면과 메뉴가 뜨는지 확인합니다.
2. CSV 참조 옵션을 켠 뒤 SAC/DAC/KAC grant 직전까지 진행합니다.
3. `CSV/API 사전 검증` 표가 출력되는지 확인합니다.
4. CSV의 UUID나 이름을 일부러 틀리게 바꾸면 `PRECHECK_FAIL` 후 실제 변경이 중단되어야 합니다.
5. DAC endpoint 검색을 두 번 실행했을 때 두 번째부터 cache 재사용 메시지가 보이면 정상입니다.
