# 변경 이력

## 2026-06

* SAC/DAC/KAC 권한 부여와 회수를 제품별 메뉴로 분리했습니다.
* 변경 전 API 사전 대조와 변경 후 API 검증을 추가했습니다.
* 반복 조회를 줄이기 위해 사용자, role, DB, privilege, 태그 조회 cache를 적용했습니다.
* DAC DB 후보 검색에서 DB명, endpoint, IP, 태그 기반 흐름을 지원합니다.
* CSV 기록은 API 검증까지 성공한 작업만 append하도록 구성했습니다.
* 실행 진입점을 `acl_cli.py`, 패키지를 `acl_tool`로 변경했습니다.
