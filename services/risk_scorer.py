# services/risk_scorer.py

# SafeQR의 여러 분석 결과를 합쳐
# 최종 위험 점수와 위험 등급을 계산하는 모듈


# 외부 검사 실패 보정 (Rafsanjani 2023 QsecR / 2024 "특징 평가 방법")
# 외부 검사 결과가 없으면(응답 실패, 또는 무료 호스팅/IP라 도메인 나이를 조회하지 않음) 그 검사의 몫을 가장 강한 단서에 몰아줌
# 단서가 이 점수 이상일 때만, 실패한 검사 하나당 x1.3
# (측정: 새 피싱 450개 +3개, 정상 844개 오탐 0)
MISSING_MIN_STRONG = 25
MISSING_FACTOR = 1.3


def calculate_risk(lexical, brand_similarity, external_db=None, domain_trust=None, page=None,
                   compensate_missing=False):
    """
    각 탐지 모듈의 결과를 받아 최종 위험도를 계산한다.

    lexical          : URL 어휘/구조 분석 결과
    brand_similarity : 브랜드 유사도 분석 결과
    external_db      : 외부 위협 DB 분석 결과 (팀원 담당)
    domain_trust     : 도메인 신뢰도 분석 결과 (팀원 담당)
    page             : 페이지 내용(HTML) 분석 결과
    compensate_missing : 외부 검사를 시도했는데 실패한 경우에만 True
                         (실험에서 일부러 검사를 뺀 경우와 구분하기 위함)
    """

    # 최종 점수
    total_score = 0

    # 최종 위험 판단 근거
    all_reasons = []

    # 0. 외부 검사 실패 보정
    if compensate_missing:
        missing = sum(x is None for x in (external_db, domain_trust, page))
        strongest = max((lexical or {}).get("score", 0), (brand_similarity or {}).get("score", 0))
        if missing and strongest >= MISSING_MIN_STRONG:
            total_score += round(strongest * (MISSING_FACTOR ** missing - 1))
            all_reasons.append("일부 외부 검사를 할 수 없어, 가장 강한 위험 단서의 비중을 높였습니다.")

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