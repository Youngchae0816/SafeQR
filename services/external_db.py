import json
import os
import urllib.request


# Google Safe Browsing API 주소
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="


# Google Safe Browsing 조회
# True = 위험 목록에 있음, False = 없음, None = 조회 못 함
def check_safe_browsing(url: str):

    # API 키는 코드에 직접 쓰지 않고 환경변수에서 읽음
    api_key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not api_key:
        return None

    # Google에 보낼 요청 내용
    body = {
        "client": {"clientId": "safeqr", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",                          # 악성코드
                "SOCIAL_ENGINEERING",               # 피싱
                "UNWANTED_SOFTWARE",                # 원치 않는 소프트웨어
                "POTENTIALLY_HARMFUL_APPLICATION"   # 유해 앱
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    request = urllib.request.Request(
        SAFE_BROWSING_URL + api_key,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}
    )

    # 외부 서버가 느리거나 실패해도 전체 분석은 계속 진행
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.load(response)
    except Exception as e:
        print(f"Safe Browsing 조회 실패: {e}")
        return None

    # 위험 사이트면 matches 목록이 오고, 안전하면 빈 응답이 옴
    return bool(data.get("matches"))


# 외부 위협 DB 검사: Google Safe Browsing
def check_external_db(url: str):

    safe_browsing = check_safe_browsing(url)

    if safe_browsing is None:
        return None

    # 공식 DB에 등록된 위험 사이트는 바로 위험 판정
    if safe_browsing:
        return {
            "score": 100,
            "safe_browsing": True,      # True = 탐지됨
            "reasons": ["Google Safe Browsing에 위험 사이트로 등록되어 있습니다."]
        }

    return {
        "score": 0,
        "safe_browsing": False,
        "reasons": []
    }
