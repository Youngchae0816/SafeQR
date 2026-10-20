
from urllib.parse import urlparse
import ipaddress

# 비교할 주요 브랜드와 공식 도메인
BRANDS = {
    "paypal": ("PayPal", ["paypal.com"]),
    "google": ("Google", ["google.com"]),
    "naver": ("Naver", ["naver.com"]),
    "kakao": ("Kakao", ["kakao.com"]),
    "samsung": ("Samsung", ["samsung.com"]),
    "apple": ("Apple", ["apple.com"]),
    "microsoft": ("Microsoft", ["microsoft.com"]),
    "instagram": ("Instagram", ["instagram.com"]),
    "facebook": ("Facebook", ["facebook.com"]),
    "youtube": ("YouTube", ["youtube.com"]),
}


# 두 문자열 사이의 편집거리 계산
def levenshtein_distance(str1: str, str2: str) -> int:
    rows = len(str1) + 1
    cols = len(str2) + 1

    dp = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        dp[i][0] = i

    for j in range(cols):
        dp[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if str1[i - 1] == str2[j - 1] else 1

            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )

    return dp[-1][-1]


# URL에서 호스트명 추출
def extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().rstrip(".")


# 공식 도메인 및 하위 도메인 확인
def is_official_domain(hostname: str, official_domain: str) -> bool:
    return (
        hostname == official_domain
        or hostname.endswith("." + official_domain)
    )


# 분석할 등록 도메인 이름 추출
def extract_domain_name(url: str) -> str:
    hostname = extract_hostname(url)

    if not hostname:
        return ""

    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        pass

    # 일반적인 도메인 형식에서 이름 추출
    # apps.apple.com -> apple
    # apple-login.com -> apple-login
    parts = hostname.split(".")

    if len(parts) < 2:
        return ""

    return parts[-2]


# 브랜드 유사도 분석
def analyze_brand_similarity(url: str) -> dict:
    hostname = extract_hostname(url)
    domain_name = extract_domain_name(url)

    score = 0
    reasons = []

    # 공식 도메인이라면 브랜드 사칭 점수 부여하지 않음
    for brand_key, (brand_name, official_domains) in BRANDS.items():
        for official_domain in official_domains:
            if is_official_domain(hostname, official_domain):
                return {
                    "score": 0,
                    "reasons": []
                }

    # 하이픈 기준으로 문자열 분리
    parts = domain_name.split("-")

    for part in parts:
        if not part:
            continue

        for brand_key, (brand_name, official_domains) in BRANDS.items():

            # 비공식 도메인에서 브랜드명을 그대로 사용하는 경우
            if part == brand_key:
                score += 30
                reasons.append(
                    f"비공식 도메인에서 {brand_name} 브랜드명이 사용되었습니다."
                )
                continue

            distance = levenshtein_distance(part, brand_key)

            if distance == 1:
                score += 30
                reasons.append(
                    f"{brand_name}과 매우 유사한 문자열 '{part}'이 감지되었습니다."
                )

            elif distance == 2 and len(brand_key) >= 5:
                score += 15
                reasons.append(
                    f"{brand_name}과 유사한 문자열 '{part}'이 감지되었습니다."
                )

    # 최종 점수 최대 40점
    score = min(score, 40)

    return {
        "score": score,
        "reasons": reasons
    }
