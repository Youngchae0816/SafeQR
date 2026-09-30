from fastapi import FastAPI
from pydantic import BaseModel

# 우리가 만든 URL 분석 함수 가져오기
from services.url_analyzer import analyze_url_structure


# FastAPI 앱 생성
app = FastAPI(
    title="SafeQR API",
    description="SafeQR 악성 URL 탐지 백엔드 서버",
    version="1.0.0"
)


# 안드로이드 앱에서 받을 데이터 형식
class URLRequest(BaseModel):
    url: str


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
@app.post("/analyze")
def analyze_url(request: URLRequest):

    # 안드로이드 앱에서 전달받은 URL
    url = request.url

    # url_analyzer.py의 분석 함수 실행
    result = analyze_url_structure(url)

    # 분석 점수
    score = result["score"]

    # 임시 위험도 기준
    if score >= 40:
        level = "danger"
    elif score >= 20:
        level = "warning"
    else:
        level = "safe"

    # 안드로이드 앱으로 전달할 최종 결과
    return {
        "url": url,
        "domain": result["domain"],
        "score": score,
        "level": level,
        "reasons": result["reasons"]
    }