# API 호출 구조

이 문서는 권한 변경 시 API가 어떤 순서로 호출되는지, 어떤 구간이 서버에 부담이 될 수 있는지 정리합니다.

## 부담 기준

| 부담 | 의미 |
|---|---|
| 낮음 | 1~3회 정도의 직접 조회 |
| 중간 | 목록 조회 1회와 선택 객체 detail 조회 |
| 높음 | page scan 또는 후보별 detail 조회 |
| 변경 | 서버 데이터를 바꾸는 API |

## 공통 안전장치

| 장치 | 설명 |
|---|---|
| 최종 확인 | 실행 계획 표를 보여준 뒤 `y`를 입력해야 변경 API를 호출합니다. |
| CSV/API 사전 대조 | CSV 참조로 찾은 대상은 변경 전에 API와 다시 비교합니다. |
| 변경 후 검증 | 변경 API 호출 후 다시 GET으로 결과를 확인합니다. |
| 실패 시 CSV 미기록 | API 검증에 성공한 건만 이력 CSV에 기록합니다. |

## CSV/API 사전 대조

CSV 참조 옵션이 켜져 있고 선택 대상이 CSV에 있으면 실제 변경 API 호출 전에 API로 다시 확인합니다.

| 영역 | CSV 기준 | API 확인 | 다르거나 없을 때 |
|---|---|---|---|
| SAC | role UUID/name | role name 조회 | `PRECHECK_FAIL` 출력 후 중단 |
| DAC | group/cluster UUID, DB명, type, endpoint | connection detail 조회 | `PRECHECK_FAIL` 출력 후 중단 |
| KAC | role UUID/name | KAC role 목록 조회 | `PRECHECK_FAIL` 출력 후 중단 |

## 호출 흐름 요약

### 사용자 조회

```text
GET /api/external/v3/iam/users?name={keyword}
GET /api/external/v3/iam/users?loginId={keyword}
GET /api/external/v3/iam/users?email={keyword}
GET /api/external/v3/iam/users?pageNumber={page}&pageSize={pageSize}
```

### SAC role grant/revoke

| 순서 | API | 부담 | 설명 |
|---:|---|---|---|
| 1 | `GET /api/external/v2/sac/roles?name=...` | 낮음 | role 후보 검색 |
| 2 | `GET /api/external/v2/sac/roles/{roleUuid}` | 낮음 | policy 없는 role 부여 차단 |
| 3 | 사용자 조회 | 낮음~높음 | 사용자 후보 선택 |
| 4 | `GET /api/external/v2/sac/access-controls/{userUuid}/roles` | 낮음~중간 | 기존 권한 확인 |
| 5 | `POST` 또는 `DELETE /api/external/v2/sac/access-controls/{userUuid}/roles` | 변경 | role 부여/회수 |
| 6 | 기존 권한 재조회 | 낮음~중간 | 변경 후 검증 |

### DAC DB grant/revoke

| 순서 | API | 부담 | 설명 |
|---:|---|---|---|
| 1 | `GET /api/external/v2/dac/connections?...connectionName=...` | 중간 | DB명 후보 검색 |
| 2 | `GET /api/external/v2/dac/connections/{connectionGroupUuid}` | 중간 | 실제 grant cluster UUID 확인 |
| 3 | `GET /api/external/v2/dac/connections/clusters/{clusterUuid}/instances` | 높음 | endpoint/IP 표시 |
| 4 | `GET /api/external/v2/privileges?...` | 중간 | privilege 후보 검색 |
| 5 | 사용자 조회 | 낮음~높음 | 사용자 후보 선택 |
| 6 | `POST /api/external/v2/dac/access-controls/{userUuid}/bulk-grant` | 변경 | 여러 DB cluster 권한 부여 |
| 7 | `GET /api/external/v2/dac/access-controls/{userUuid}` | 중간 | 변경 후 검증 |

### KAC role grant/revoke

| 순서 | API | 부담 | 설명 |
|---:|---|---|---|
| 1 | `GET /api/external/v2/kac/access-controls/roles` | 중간 | KAC role 목록 조회 |
| 2 | 사용자 조회 | 낮음~높음 | 사용자 후보 선택 |
| 3 | `GET /api/external/v2/kac/access-controls/users/{userUuid}/roles` | 낮음~중간 | 기존 권한 확인 |
| 4 | `POST` 또는 `DELETE /api/external/v2/kac/access-controls/users/{userUuid}/roles` | 변경 | role 부여/회수 |
| 5 | 사용자 KAC role 재조회 | 낮음~중간 | 변경 후 검증 |

## 예시 payload

```json
{
  "expiryAt": "2027-06-06T23:59:59Z",
  "roleUuids": ["00000000-0000-4000-8000-000000000000"],
  "clusterUuid": "11111111-1111-4111-8111-111111111111",
  "privilegeUuid": "22222222-2222-4222-8222-222222222222"
}
```

## scan/cache 주의

| 상황 | 동작 |
|---|---|
| DAC DB명 검색 실패 | connection 목록 page scan과 detail 조회로 넘어갈 수 있음 |
| 태그 API scan | 객체별 detail 조회가 필요할 수 있음 |
| KAC role 검색 | role 목록을 한 번 조회해 메모리 cache에서 검색 |
| `MAX_*_PAGES = 0` | pagination이 끝날 때까지 조회 |
