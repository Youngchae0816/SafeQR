
import os
import requests
from dotenv import load_dotenv

# .env 파일에 저장된 환경변수 불러오기
load_dotenv()

# Google Safe Browsing API 키
API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Google Safe Browsing API 주소
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_url_safety(url):
    # API 키가 없는 경우
    if not API_KEY:
        return {
            "status": "error",
            "message": "API 키가 설정되지 않았습니다."
        }

    # Google API에 전달할 요청 데이터
    payload = {
        "client": {
            "clientId": "safeqr-project",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        # 외부 API에 URL 검사 요청
        response = requests.post(
            API_URL,
            params={"key": API_KEY},
            json=payload,
            timeout=10
        )

        # HTTP 오류 확인
        response.raise_for_status()

        result = response.json()

        # 알려진 악성 URL이 탐지된 경우
        if result.get("matches"):
            return {
                "status": "danger",
                "message": "Google Safe Browsing에서 위험 URL로 탐지되었습니다.",
                "matches": result["matches"]
            }

        # 탐지 목록에 없는 경우
        return {
            "status": "safe",
            "message": "Google Safe Browsing에서 알려진 위협이 탐지되지 않았습니다."
        }

    except requests.RequestException as e:
        return {
            "status": "error",
            "message": str(e)
        }
