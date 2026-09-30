from urllib.parse import urlparse


# URL 자체의 특징을 분석하는 함수
def analyze_url_structure(url: str):

    # 위험 점수
    score = 0

    # 위험하다고 판단한 이유를 저장할 리스트
    reasons = []

    # 피싱 사이트에서 자주 사용되는 의심 키워드
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "bank"
    ]

    # 대소문자 구분 없이 검사하기 위해 소문자로 변환
    lower_url = url.lower()

    # URL에서 도메인 부분 추출
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # 1. 의심 키워드 검사
    for word in suspicious_words:
        if word in lower_url:
            score += 10
            reasons.append(f"의심 키워드 포함: {word}")

    # 2. URL 길이 검사
    if len(url) > 75:
        score += 10
        reasons.append("URL이 비정상적으로 깁니다.")

    # 3. 하이픈 개수 검사
    hyphen_count = domain.count("-")

    if hyphen_count >= 2:
        score += 10
        reasons.append("도메인에 하이픈이 여러 개 포함되어 있습니다.")

    # 분석 결과 반환
    return {
        "score": score,
        "domain": domain,
        "reasons": reasons
    }