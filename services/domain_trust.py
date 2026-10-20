import json
import os
import urllib.request
from datetime import date, datetime
from urllib.parse import urlencode, urlparse

from services.url_analyzer import extract_domain, is_user_content_platform


# .kr 도메인 조회용 (공공데이터포털 - 한국인터넷진흥원 WHOIS)
KISA_WHOIS_URL = "https://apis.data.go.kr/B551505/whois/domain_name?"

# .com 등 해외 도메인 조회용 (RDAP: WHOIS의 공식 후속 표준, 키 필요 없음)
RDAP_URL = "https://rdap.org/domain/"
RDAP_HEADERS = {
    "User-Agent": "SafeQR/1.0 (+https://github.com/Youngchae0816/SafeQR)",
    "Accept": "application/rdap+json",
}

# 이 기간보다 최근에 만들어진 도메인은 위험 신호로 봄
# (피싱 사이트는 대부분 만든 지 며칠~몇 주 안에 사용되고 버려짐)
NEW_DOMAIN_DAYS = 30


# 도메인 등록일 가져오기 (실패하면 None)
def get_registration_date(domain: str, suffix: str):

    # .kr 도메인 -> KISA
    if suffix == "kr" or suffix.endswith(".kr"):
        api_key = os.environ.get("KISA_WHOIS_API_KEY")
        if not api_key:
            return None
        query = urlencode({"serviceKey": api_key, "query": domain, "answer": "json"})
        with urllib.request.urlopen(KISA_WHOIS_URL + query, timeout=5) as response:
            data = json.load(response)
        # 예) "1998. 05. 26."
        reg_date = data["response"]["whois"]["krdomain"]["regDate"]
        return datetime.strptime(reg_date.strip(), "%Y. %m. %d.").date()

    # 그 외 -> RDAP
    # 프로그램 이름표(User-Agent)가 없으면 .org 등 일부 등록 기관이 거부함(403)
    request = urllib.request.Request(RDAP_URL + domain, headers=RDAP_HEADERS)
    with urllib.request.urlopen(request, timeout=5) as response:
        data = json.load(response)
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            # 예) "1997-09-12T04:00:00Z" -> 앞 10글자만 사용
            return date.fromisoformat(event["eventDate"][:10])
    return None


# 도메인 신뢰도 분석 (도메인이 만들어진 지 얼마나 됐는지)
def check_domain_trust(url: str):

    ext = extract_domain(url)

    # IP 주소이거나, 무료 호스팅·파일 공유 같은 사용자 콘텐츠 플랫폼이면 조회하지 않음
    # (godaddysites.com, netlify.app 같은 플랫폼 자체의 나이가 나와서 피싱도 "오래된 도메인"이 됨)
    host = (urlparse(url).hostname or "").lower()
    if not ext.domain or not ext.suffix or ext.is_private or is_user_content_platform(host):
        return None

    domain = f"{ext.domain}.{ext.suffix}"

    # 외부 서버가 느리거나 실패해도 전체 분석은 계속 진행
    try:
        reg_date = get_registration_date(domain, ext.suffix)
    except Exception as e:
        print(f"WHOIS 조회 실패 ({domain}): {e}")
        return None

    if reg_date is None:
        return None

    age_days = (date.today() - reg_date).days

    if age_days < NEW_DOMAIN_DAYS:
        return {
            "score": 30,
            "domain_age_days": age_days,
            "reasons": [f"만들어진 지 {age_days}일밖에 안 된 신규 도메인입니다."]
        }

    return {
        "score": 0,
        "domain_age_days": age_days,
        "reasons": []
    }
