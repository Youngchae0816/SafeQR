
# services/risk_scorer.py

# 여러 분석 결과를 종합하여 최종 위험도를 계산


# 외부 검사 실패 보정 (Rafsanjani 2023 QsecR / 2024 "특징 평가 방법")
# 외부 검사가 실패해서 결과가 없으면 그 검사의 몫을 가장 강한 단서에 몰아줌
# 단서가 이 점수 이상일 때만, 실패한 검사 하나당 x1.3
# 무료 호스팅·IP라서 도메인 나이를 일부러 조회하지 않은 경우는 실패로 세지 않음
# (실패로 셌더니 pages.dev에 올린 정상 개인 프로젝트가 100점까지 올라감)
MISSING_MIN_STRONG = 25
MISSING_FACTOR = 1.3


def calculate_risk(lexical, brand_similarity, external_db=None, domain_trust=None, page=None,
                   compensate_missing=False, domain_trust_skipped=False):
    """
    각 탐지 모듈의 결과를 받아 최종 위험도를 계산한다.

    lexical          : URL 어휘/구조 분석 결과
    brand_similarity : 브랜드 유사도 분석 결과
    external_db      : 외부 위협 DB 분석 결과
    domain_trust     : 도메인 신뢰도 분석 결과
    page             : 페이지 내용(HTML) 분석 결과
    compensate_missing : 외부 검사를 시도했는데 실패한 경우에만 True
                         (실험에서 일부러 검사를 뺀 경우와 구분하기 위함)
    domain_trust_skipped : 무료 호스팅·IP라 도메인 나이를 조회하지 않은 경우 True
    """

    # 최종 점수
    total_score = 0

    # 위험 판단 근거
    all_reasons = []

    # 0. 외부 검사 실패 보정
    if compensate_missing:
        missing = (
            int(external_db is None)
            + int(domain_trust is None and not domain_trust_skipped)
            + int(page is None)
        )

        strongest = max(
            (lexical or {}).get("score", 0),
            (brand_similarity or {}).get("score", 0)
        )

        if missing and strongest >= MISSING_MIN_STRONG:
            total_score += round(
                strongest * (MISSING_FACTOR ** missing - 1)
            )

            all_reasons.append(
                "일부 외부 검사를 할 수 없어, 가장 강한 위험 단서의 비중을 높였습니다."
            )

    # 1. URL 어휘/구조 분석
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
        safe_browsing = external_db.get("safe_browsing")

        # Google Safe Browsing에서 악성 URL 탐지
        if safe_browsing is True or status == "danger":

            total_score = max(total_score, 100)

            all_reasons.extend(external_db.get("reasons", []))

            if not external_db.get("reasons"):
                all_reasons.append(
                    "Google Safe Browsing에서 악성 URL로 탐지되었습니다."
                )

        # 외부 API 오류
        elif status == "error":

            total_score = max(total_score, 30)

            all_reasons.append(
                "외부 악성 URL 검사에 실패하여 안전 여부를 확인할 수 없습니다."
            )

        # 정상 검사 결과
        else:
            total_score += external_db.get("score", 0)
            all_reasons.extend(external_db.get("reasons", []))

    # 4. 도메인 신뢰도 분석
    if domain_trust:
        total_score += domain_trust.get("score", 0)
        all_reasons.extend(domain_trust.get("reasons", []))

    # 5. 페이지 내용 분석
    if page:
        total_score += page.get("score", 0)
        all_reasons.extend(page.get("reasons", []))

    # 점수가 100점을 넘지 않도록 제한
    total_score = max(0, min(total_score, 100))

    # 최종 위험 등급
    if total_score >= 60:
        level = "danger"

    elif total_score >= 30:
        level = "warning"

    else:
        level = "safe"

    # 중복된 위험 판단 근거 제거
    all_reasons = list(dict.fromkeys(all_reasons))

    return {
        "score": total_score,
        "level": level,
        "reasons": all_reasons
    }
