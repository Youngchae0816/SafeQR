
# services/risk_scorer.py

# 여러 분석 결과를 종합하여 최종 위험도를 계산


def calculate_risk(lexical, brand_similarity, external_db=None, domain_trust=None):

    # 최종 위험 점수
    total_score = 0

    # 위험 판단 근거
    all_reasons = []

    # 1. URL 구조 분석
    if lexical:
        total_score += lexical.get("score", 0)
        all_reasons.extend(lexical.get("reasons", []))

    # 2. 브랜드 유사도 분석
    if brand_similarity:
        total_score += brand_similarity.get("score", 0)
        all_reasons.extend(brand_similarity.get("reasons", []))

    # 3. Google Safe Browsing API 결과
    if external_db:

        status = external_db.get("status")

        if status == "danger":
            # Google에서 알려진 악성 URL로 탐지한 경우
            total_score = max(total_score, 100)

            all_reasons.append(
                "Google Safe Browsing에서 악성 URL로 탐지되었습니다."
            )

        elif status == "error":
            # 외부 API 오류가 발생한 경우
            # 정상 검사 결과와 구분하여 주의 처리
            total_score = max(total_score, 30)

            all_reasons.append(
                "외부 악성 URL 검사에 실패하여 안전 여부를 확인할 수 없습니다."
            )

        elif status == "safe":
            # 알려진 위협이 탐지되지 않은 경우
            # 기존 URL 분석 점수는 유지
            pass

    # 4. 도메인 신뢰도 분석
    if domain_trust:
        total_score += domain_trust.get("score", 0)
        all_reasons.extend(domain_trust.get("reasons", []))

    # 점수 최대 100점
    total_score = min(total_score, 100)

    # 최종 위험 등급
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
