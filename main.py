from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# 요청/응답 데이터 형식
from models.schemas import URLRequest, URLAnalysisResponse

# 분석 기능 가져오기
from services.url_analyzer import analyze_url_structure
from services.brand_similarity import analyze_brand_similarity
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


# URL 분석 API
@app.post("/analyze", response_model=URLAnalysisResponse)
def analyze_url(request: URLRequest):

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

    # 3. 외부 위협 DB 분석
    # 다른 팀원이 담당하므로 현재는 연결 전
    external_db_result = None

    # 4. 도메인 신뢰도 분석
    # 다른 팀원이 담당하므로 현재는 연결 전
    domain_trust_result = None

    # 여러 분석 결과를 종합하여 최종 위험도 계산
    risk_result = calculate_risk(
        lexical=lexical_result,
        brand_similarity=brand_result,
        external_db=external_db_result,
        domain_trust=domain_trust_result
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
            "domain_trust": domain_trust_result
        },

        # 최종 위험 판단 근거
        "reasons": risk_result["reasons"]
    }