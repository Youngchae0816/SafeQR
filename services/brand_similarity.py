from urllib.parse import urlparse


# 비교할 주요 브랜드 목록
# 추후 필요한 브랜드를 추가할 수 있음
BRANDS = {
    "paypal": "PayPal",
    "google": "Google",
    "naver": "Naver",
    "kakao": "Kakao",
    "samsung": "Samsung",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "instagram": "Instagram",
    "facebook": "Facebook",
    "youtube": "YouTube",
}


# 두 문자열 사이의 편집거리(Levenshtein Distance) 계산
def levenshtein_distance(str1: str, str2: str) -> int:
    rows = len(str1) + 1
    cols = len(str2) + 1

    # 거리 계산용 2차원 배열 생성
    dp = [[0] * cols for _ in range(rows)]

    # 초기값 설정
    for i in range(rows):
        dp[i][0] = i

    for j in range(cols):
        dp[0][j] = j

    # 편집거리 계산
    for i in range(1, rows):
        for j in range(1, cols):

            # 문자가 같으면 비용 0, 다르면 비용 1
            cost = 0 if str1[i - 1] == str2[j - 1] else 1

            dp[i][j] = min(
                dp[i - 1][j] + 1,       # 삭제
                dp[i][j - 1] + 1,       # 삽입
                dp[i - 1][j - 1] + cost # 교체
            )

    return dp[-1][-1]


# URL에서 실제 비교할 도메인 이름 추출
def extract_domain_name(url: str) -> str:
    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # 포트 번호 제거
    domain = domain.split(":")[0]

    # www 제거
    if domain.startswith("www."):
        domain = domain[4:]

    # paypal.com -> paypal
    # paypa1-login.com -> paypa1-login
    domain_name = domain.split(".")[0]

    return domain_name


# 브랜드 유사도 분석
def analyze_brand_similarity(url: str) -> dict:

    domain_name = extract_domain_name(url)

    score = 0
    reasons = []

    # 하이픈으로 나누어서 각각 검사
    # ex) paypa1-secure-login -> paypa1, secure, login
    parts = domain_name.split("-")

    for part in parts:

        for brand_key, brand_name in BRANDS.items():

            # 실제 브랜드와 완전히 같은 경우는 의심하지 않음
            if part == brand_key:
                continue

            distance = levenshtein_distance(part, brand_key)

            # 한 글자 차이
            if distance == 1:
                score += 30

                reasons.append(
                    f"{brand_name}과 매우 유사한 문자열 '{part}'이 감지되었습니다."
                )

            # 두 글자 차이
            elif distance == 2 and len(brand_key) >= 5:
                score += 15

                reasons.append(
                    f"{brand_name}과 유사한 문자열 '{part}'이 감지되었습니다."
                )

    # 점수가 너무 커지지 않도록 제한
    score = min(score, 40)

    return {
        "score": score,
        "reasons": reasons
    }