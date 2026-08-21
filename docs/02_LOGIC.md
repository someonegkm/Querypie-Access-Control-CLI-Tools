# 로직

## 전체 흐름

```text
토큰 입력
  -> 토큰 유효성 확인
  -> SAC/DAC/KAC 영역 선택
  -> 작업 선택
  -> 대상 객체 선택
  -> 사용자 선택
  -> 실행 계획 표 출력
  -> 최종 확인
  -> CSV/API 사전 대조
  -> 변경 API 호출
  -> 변경 후 API 검증
  -> 성공 건만 CSV 기록
```

## 모듈 역할

| 파일 | 역할 |
|---|---|
| `main.py` | 시작점, 메뉴 구성, 공통 도구 연결 |
| `api.py` | API 요청, 토큰 검증 |
| `acl.py` | SAC role grant/revoke |
| `os_account.py` | SAC OS 계정 등록 |
| `dac.py` | DAC DB grant/revoke, DB 후보/privilege 선택 |
| `kac.py` | KAC role grant/revoke |
| `resolver.py` | 사용자와 SAC role 후보 선택 |
| `tag_lookup.py` | SAC/DAC/KAC 태그 기반 후보 조회 |
| `asset_reference.py` | 권한 대상/태그 리퍼런스 CSV read-only 인덱스 |
| `local_reference.py` | CSV 기록 입력 기본값 read-only 인덱스 |
| `report.py` | Excel 호환 CSV 기록 |
| `view.py` | 콘솔 표 출력 |
| `api_utils.py` | API 응답 list 변환, URL quote, 페이지 조회, 번호 선택 |
| `user_utils.py` | 사용자 응답 파싱과 내부/협력사 도메인 분류 |
| `sac_role_utils.py` | SAC role 이름 파싱, 기본 만료일, 후보 주의 규칙 |

## 후보 선택 규칙

### 사용자

| 입력 | 검색 순서 |
|---|---|
| `@` 포함 | email -> loginId -> name |
| 일반 문자열 | name -> loginId -> email |
| 직접 검색 실패 | 사용자 목록 fallback scan |

동명이인이 있으면 후보 표를 보여주고, 사용자가 번호를 선택합니다.

### SAC role

| 방식 | 설명 |
|---|---|
| API 이름 검색 | role name query로 좁게 조회 |
| SAC role cache | SAC role 목록을 한 번 읽고 메모리에서 검색 |
| 태그 검색 | 서버그룹 태그에서 role 후보 검색어를 추출 |
| CSV 참조 | `sac_roles.csv`에서 후보를 먼저 찾음 |

### DAC DB

| 방식 | 설명 |
|---|---|
| DB명 검색 | connection name으로 먼저 조회 |
| detail 조회 | connection group detail에서 실제 grant cluster UUID 확인 |
| endpoint 검색 | 이름 검색 실패 또는 endpoint/IP 입력이면 전체 scan |
| CSV 참조 | `cluster_groups.csv`, `clusters.csv`에서 후보를 먼저 찾음 |

자동 제외:

| 조건 | 처리 |
|---|---|
| `CUSTOM` database | 후보에서 제외 |
| 이름에 `internal-only` 포함 | 후보에서 제외 |

## cache 원칙

전체 scan은 한 번 하면 같은 실행 세션에서 메모리에 보관합니다.

| cache | 다시 쓰는 곳 |
|---|---|
| SAC role cache | SAC role 검색/미리보기 |
| DAC full scan cache | DB명/endpoint fallback 검색 |
| SAC/DAC/KAC tag cache | 태그 기반 후보 검색 |
| KAC role cache | KAC role 검색/태그 매칭 |
| detail cache | 같은 UUID 재조회 방지 |
| user search cache | 같은 사용자 입력 재조회 방지 |
| DAC privilege cache | privilege 후보 재사용 |

cache는 실행 중 메모리에만 있고, 프로그램을 종료하면 사라집니다.

## 확장 기준

| 추가 대상 | 위치 |
|---|---|
| 새 메뉴 | `menus.py`, `main.py` |
| 새 권한 영역 | 별도 tool 클래스 |
| 새 후보 검색 | repository 클래스 검색 함수 |
| 새 CSV 기록 | `report.py` append 함수 |
| 새 태그 lookup | `asset_tags.py`, `tag_lookup.py` |
| 새 API 흐름 문서 | `03_API.md` |

서버 데이터를 수정하는 기능은 권한 부여/회수/OS 계정 등록에 한정합니다.
