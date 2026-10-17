# services/risk_scorer.py

# SafeQR의 여러 분석 결과를 합쳐
# 최종 위험 점수와 위험 등급을 계산하는 모듈


def calculate_risk(lexical, brand_similarity, external_db=None, domain_trust=None, page=None):
    """
    각 탐지 모듈의 결과를 받아 최종 위험도를 계산한다.

    lexical          : URL 어휘/구조 분석 결과
    brand_similarity : 브랜드 유사도 분석 결과
    external_db      : 외부 위협 DB 분석 결과 (팀원 담당)
    domain_trust     : 도메인 신뢰도 분석 결과 (팀원 담당)
    page             : 페이지 내용(HTML) 분석 결과
    """

    # 최종 점수
    total_score = 0

    # 최종 위험 판단 근거
    all_reasons = []

    # 1. URL 어휘/구조 분석 점수
    if lexical:
        total_score += lexical.get("score", 0)
        all_reasons.extend(lexical.get("reasons", []))

    # 2. 브랜드 유사도 분석 점수
    if brand_similarity:
        total_score += brand_similarity.get("score", 0)
        all_reasons.extend(brand_similarity.get("reasons", []))

    # 3. 외부 위협 DB 결과
    # 현재는 다른 팀원이 담당하므로 결과가 들어왔을 때만 반영
    if external_db:
        total_score += external_db.get("score", 0)
        all_reasons.extend(external_db.get("reasons", []))

    # 4. 도메인 신뢰도 결과
    # 현재는 다른 팀원이 담당하므로 결과가 들어왔을 때만 반영
    if domain_trust:
        total_score += domain_trust.get("score", 0)
        all_reasons.extend(domain_trust.get("reasons", []))

    # 5. 페이지 내용 분석 결과
    # 사이트 접속에 실패하면 결과가 없으므로 들어왔을 때만 반영
    if page:
        total_score += page.get("score", 0)
        all_reasons.extend(page.get("reasons", []))

    # 점수가 100점을 넘지 않도록 제한
    total_score = min(total_score, 100)

    # 최종 위험 등급 결정
    if total_score >= 60:
        level = "danger"
    elif total_score >= 30:
        level = "warning"
    else:
        level = "safe"

    return {
        "score": total_score,
        "level": level,
        "reasons": all_reasons
    }