import os
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

# .env 파일에 적힌 API 키를 환경변수로 불러오기 (파일이 없으면 건너뜀)
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                key, value = line.strip().split("=", 1)
                os.environ.setdefault(key, value)

# 요청/응답 데이터 형식
from models.schemas import URLRequest, URLAnalysisResponse

# 분석 기능 가져오기
from services.url_analyzer import analyze_url_structure
from services.brand_similarity import analyze_brand_similarity
from services.external_db import check_external_db
from services.domain_trust import check_domain_trust
from services.page_analyzer import analyze_page
from services.risk_scorer import calculate_risk
from services.url_validator import validate_url
from services.error_handler import global_exception_handler


# FastAPI 앱 생성
app = FastAPI(
    title="SafeQR API",
    description="SafeQR 악성 URL 탐지 백엔드 서버",
    version="1.0.0"
)

# 프론트엔드에서 백엔드 API에 접근할 수 있도록 CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 예상하지 못한 서버 오류를 공통 형식으로 처리
app.add_exception_handler(Exception, global_exception_handler)


# 기본 주소 접속 테스트
@app.get("/")
def root():
    return {
        "message": "SafeQR Backend Server"
    }


# 서버 정상 작동 확인용
@app.get("/health")
def health_check():
    return {
        "status": "ok"
    }


# 같은 IP에서 1분에 분석할 수 있는 최대 횟수
# (서버가 외부 사이트에 직접 접속하므로 무제한 호출을 막음)
RATE_LIMIT = 30
recent_requests = defaultdict(deque)


# ponytail: 서버 메모리에 기록 - 서버 1대 기준, 여러 대로 늘리면 Redis 같은 공용 저장소 필요
def check_rate_limit(ip: str):
    now = time.monotonic()
    times = recent_requests[ip]
    while times and now - times[0] > 60:
        times.popleft()
    if len(times) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.")
    times.append(now)


# URL 분석 API
@app.post("/analyze", response_model=URLAnalysisResponse)
def analyze_url(request: URLRequest, http_request: Request):

    check_rate_limit(http_request.client.host if http_request.client else "unknown")

    # 안드로이드 앱에서 전달받은 URL
    url = request.url.strip()

    # URL 형식 검증
    validation_result = validate_url(url)

    # 올바른 웹 URL이 아니면 분석하지 않고 오류 반환
    if not validation_result["valid"]:
        raise HTTPException(
            status_code=400,
            detail=validation_result["reason"]
        )

    # 1. URL 어휘/구조 분석
    lexical_result = analyze_url_structure(url)

    # 2. 브랜드 유사도 분석
    brand_result = analyze_brand_similarity(url)

    # 3~5는 인터넷 접속이 필요해서 동시에 실행 (하나씩 기다리면 느림)
    with ThreadPoolExecutor(max_workers=3) as pool:
        # 3. 외부 위협 DB 분석 (Google Safe Browsing)
        external_db_job = pool.submit(check_external_db, url)
        # 4. 도메인 신뢰도 분석 (WHOIS로 도메인 나이 확인)
        domain_trust_job = pool.submit(check_domain_trust, url)
        # 5. 페이지 내용 분석 (사이트에 직접 접속해서 HTML 확인)
        page_job = pool.submit(analyze_page, url)

    external_db_result = external_db_job.result()
    domain_trust_result = domain_trust_job.result()
    page_result = page_job.result()

    # 여러 분석 결과를 종합하여 최종 위험도 계산
    risk_result = calculate_risk(
        lexical=lexical_result,
        brand_similarity=brand_result,
        external_db=external_db_result,
        domain_trust=domain_trust_result,
        page=page_result
    )

    # 안드로이드 앱으로 전달할 최종 결과
    return {
        "url": url,
        "domain": lexical_result["domain"],
        "score": risk_result["score"],
        "level": risk_result["level"],

        # 각 탐지 모듈의 세부 결과
        "analysis": {
            "lexical": lexical_result,
            "brand_similarity": brand_result,
            "external_db": external_db_result,
            "domain_trust": domain_trust_result,
            "page": page_result
        },

        # 최종 위험 판단 근거
        "reasons": risk_result["reasons"]
    }