from __future__ import annotations

from dataclasses import dataclass

AUTH_HEADER_NAME = "Authorization"
AUTH_HEADER_PREFIX = "Bearer "

# 운영자가 직접 수정하는 실행 환경입니다.
# 포트폴리오 공개본은 실제 고객사/운영 환경명을 포함하지 않습니다.
# 사용 환경에 맞게 ACTIVE_ENV와 base_url을 직접 설정하세요.
# CSV의 "환경" 컬럼도 ACTIVE_ENV 값을 그대로 사용합니다.
ACTIVE_ENV = "demo"

ENVIRONMENTS = {
    "demo": {
        "base_url": "https://acl-platform.example.com",
    },
}

# 자체 서명 인증서가 있는 테스트 환경에서만 True로 바꿉니다.
INSECURE_SSL = False

# 실행 전 확인은 기본 유지합니다. 자동 실행이 필요할 때만 True로 바꿉니다.
AUTO_CONFIRM = False
SKIP_PARTNER_SUPERUSER_CONFIRM = False
SKIP_SENSITIVE_ROLE_CONFIRM = False

INTERNAL_DOMAINS = ("example.com",)
PARTNER_DOMAINS = ("partner.example.com",)

IDLE_TIMEOUT_MINUTES = 30
USER_EXPIRY_DAYS = 365
SUPERUSER_EXPIRY_DAYS = 90

USER_PAGE_SIZE = 20

# MAX_*_PAGES는 전체 scan이 과하게 길어지지 않게 막는 안전장치입니다.
# 0으로 두면 API 페이지가 끝날 때까지 조회합니다.
USER_FALLBACK_SCAN_PAGE_SIZE = 100
MAX_USER_FALLBACK_SCAN_PAGES = 20

ROLE_PAGE_SIZE = 100
MAX_ROLE_CACHE_PAGES = 100
ROLE_PREVIEW_LIMIT = 20

# False이면 SAC role을 매번 API name 검색으로 찾습니다.
# True이면 SAC 메뉴에서 role 전체 목록을 메모리에 올려 후보 미리보기와 후속 검색에 사용합니다.
USE_SAC_ROLE_CACHE = False

DAC_PAGE_SIZE = 100
MAX_DAC_CONNECTION_SCAN_PAGES = 50
DAC_CANDIDATE_DISPLAY_LIMIT = 50
DAC_EXCLUDED_NAME_KEYWORDS = ("internal-only",)
DAC_DBA_EXPIRY_DAYS = 90
DAC_DEFAULT_EXPIRY_DAYS = 365

KAC_DEFAULT_EXPIRY_DAYS = 365
KAC_CANDIDATE_DISPLAY_LIMIT = 50

TAG_LOOKUP_PAGE_SIZE = 100
MAX_TAG_LOOKUP_SCAN_PAGES = 30
TAG_LOOKUP_DISPLAY_LIMIT = 50

# CSV 이력 참고는 기본 OFF입니다.
# ON이면 CSV 기록 입력 화면에서만 이전 부문/부서/접수자/서비스 기본값을 재사용합니다.
USE_LOCAL_REFERENCE_CSV = False
LOCAL_REFERENCE_DIR = "reference"
LOCAL_REFERENCE_FILES = {
    "report_context": "report_context.csv",
}

# 권한 대상 객체를 빠르게 찾기 위한 read-only CSV입니다.
# 이 CSV는 보고서 CSV와 다릅니다. 후보를 빠르게 찾기 위한 인덱스일 뿐,
# grant/revoke는 항상 API를 호출하고 API로 다시 검증합니다.
USE_LOCAL_OBJECT_REFERENCE_CSV = False
LOCAL_OBJECT_REFERENCE_FILES = {
    # 이 두 파일은 권한 플랫폼에서 export한 DAC connection group/cluster 파일입니다.
    # 환경별로 나누지 않습니다. 필요하면 여기 경로만 바꾸면 됩니다.
    "dac_cluster_groups": "../../cluster_groups.csv",
    "dac_clusters": "../../clusters.csv",
    "sac_roles": "reference/sac_roles.csv",
    "kac_roles": "reference/kac_roles.csv",
}

# 태그 후보를 빠르게 찾기 위한 read-only CSV입니다.
# ON이면 SAC/DAC/KAC 태그 lookup이 API 전체 scan 전에 이 파일을 먼저 봅니다.
USE_LOCAL_TAG_REFERENCE_CSV = False
LOCAL_TAG_REFERENCE_FILES = {
    "sac": "reference/sac_tags.csv",
    "dac": "reference/dac_tags.csv",
    "kac": "reference/kac_tags.csv",
}

REPORT_DIR = "reports"
REPORT_PERIOD = "week"

# 비워두면 실행한 주차의 reports/AccessPlatform_Access_Report_YYYY-Www.csv를 사용합니다.
# 특정 파일에 계속 누적하려면 여기에 경로를 넣습니다.
# 예: REPORT_FILE = "reports/AccessPlatform_Access_Report_2026-W23.csv"
REPORT_FILE = ""

REPORT_HEADERS = [
    "티켓",
    "요청일",
    "처리일",
    "부문",
    "부서명",
    "접수자",
    "접수형태",
    "분류",
    "CSP",
    "권한",
    "시스템/서비스명",
    "환경",
    "내용",
    "기간",
    "상태",
    "비고",
]


@dataclass
class RuntimeConfig:
    env_name: str
    base_url: str
    csv_env: str
    insecure_ssl: bool
    auto_confirm: bool
    skip_partner_superuser_confirm: bool
    skip_sensitive_role_confirm: bool
    report_period: str
    report_file: str
    use_sac_role_cache: bool
    use_local_object_reference_csv: bool
    use_local_tag_reference_csv: bool


def load_runtime_config(use_sac_role_cache: bool | None = None) -> RuntimeConfig:
    if ACTIVE_ENV not in ENVIRONMENTS:
        valid = ", ".join(ENVIRONMENTS)
        raise ValueError(f"ACTIVE_ENV 값이 잘못되었습니다: {ACTIVE_ENV} (가능: {valid})")

    env = ENVIRONMENTS[ACTIVE_ENV]
    return RuntimeConfig(
        env_name=ACTIVE_ENV,
        base_url=env["base_url"],
        # CSV 환경은 base_url 설정과 분리하지 않습니다.
        csv_env=ACTIVE_ENV,
        insecure_ssl=INSECURE_SSL,
        auto_confirm=AUTO_CONFIRM,
        skip_partner_superuser_confirm=SKIP_PARTNER_SUPERUSER_CONFIRM,
        skip_sensitive_role_confirm=SKIP_SENSITIVE_ROLE_CONFIRM,
        report_period=REPORT_PERIOD,
        report_file=REPORT_FILE,
        use_sac_role_cache=USE_SAC_ROLE_CACHE if use_sac_role_cache is None else use_sac_role_cache,
        use_local_object_reference_csv=USE_LOCAL_OBJECT_REFERENCE_CSV,
        use_local_tag_reference_csv=USE_LOCAL_TAG_REFERENCE_CSV,
    )
