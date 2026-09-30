from fastapi import FastAPI

# 요청/응답 데이터 형식 가져오기
from models.schemas import URLRequest, URLAnalysisResponse

# URL 구조 분석 함수 가져오기
from services.url_analyzer import analyze_url_structure

# 브랜드 유사도 분석 함수 가져오기
from services.brand_similarity import analyze_brand_similarity


# FastAPI 앱 생성
app = FastAPI(
    title="SafeQR API",
    description="SafeQR 악성 URL 탐지 백엔드 서버",
    version="1.0.0"
)


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
    url = request.url

    # 1. URL 자체 구조 분석
    lexical_result = analyze_url_structure(url)

    # 2. 브랜드 유사도 분석
    brand_similarity_result = analyze_brand_similarity(url)

    # 3. 외부 위협 DB 분석
    # 아직 구현 전
    external_db_result = {
        "score": 0,
        "reasons": []
    }

    # 4. 도메인 신뢰도 분석
    # 아직 구현 전
    domain_trust_result = {
        "score": 0,
        "reasons": []
    }

    # 현재 구현된 분석 점수를 합산
    score = (
        lexical_result["score"]
        + brand_similarity_result["score"]
        + external_db_result["score"]
        + domain_trust_result["score"]
    )

    # 최종 점수는 최대 100점
    score = min(score, 100)

    # 위험도 판정
    if score >= 40:
        level = "danger"
    elif score >= 20:
        level = "warning"
    else:
        level = "safe"

    # 각 분석에서 나온 탐지 이유 합치기
    reasons = (
        lexical_result["reasons"]
        + brand_similarity_result["reasons"]
        + external_db_result["reasons"]
        + domain_trust_result["reasons"]
    )

    # 안드로이드 앱으로 전달할 최종 분석 결과
    return {
        "url": url,
        "domain": lexical_result["domain"],
        "score": score,
        "level": level,

        "analysis": {
            "lexical": lexical_result,
            "brand_similarity": brand_similarity_result,
            "external_db": external_db_result,
            "domain_trust": domain_trust_result
        },

        "reasons": reasons
    }