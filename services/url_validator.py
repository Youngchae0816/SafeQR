from urllib.parse import urlparse


def validate_url(url: str):
    """
    QR 코드에서 전달받은 문자열이
    분석 가능한 웹 URL인지 확인하는 함수
    """

    # 문자열 앞뒤 공백 제거
    url = url.strip()

    # 빈 문자열 확인
    if not url:
        return {
            "valid": False,
            "reason": "URL이 비어 있습니다."
        }

    # 비정상적으로 긴 입력 차단 (브라우저가 처리하는 주소 길이도 보통 이 정도)
    if len(url) > 2048:
        return {
            "valid": False,
            "reason": "URL이 너무 깁니다."
        }

    # URL 구조 분석
    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "valid": False,
            "reason": "올바른 URL 형식이 아닙니다."
        }

    # http 또는 https만 허용
    if parsed.scheme not in ["http", "https"]:
        return {
            "valid": False,
            "reason": "http 또는 https URL만 분석할 수 있습니다."
        }

    # 도메인이 존재하는지 확인
    if not parsed.netloc:
        return {
            "valid": False,
            "reason": "도메인이 존재하지 않습니다."
        }

    # 공백이 포함된 URL 차단
    if " " in url:
        return {
            "valid": False,
            "reason": "URL에 공백이 포함되어 있습니다."
        }

    return {
        "valid": True,
        "reason": None
    }