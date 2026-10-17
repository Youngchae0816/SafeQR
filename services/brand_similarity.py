import re
from urllib.parse import urlparse

from services.url_analyzer import extract_domain, RISKY_TLDS


# 비교할 주요 브랜드 목록
# 추후 필요한 브랜드를 추가할 수 있음
BRANDS = {
    # 국내
    "naver": "Naver",
    "kakao": "Kakao",
    "samsung": "Samsung",
    "toss": "토스",
    "coupang": "쿠팡",
    "kbstar": "KB국민은행",
    "shinhan": "신한",
    "wooribank": "우리은행",
    "hanabank": "하나은행",
    "nonghyup": "NH농협",
    "epost": "우체국",
    "cjlogistics": "CJ대한통운",
    # 해외
    "paypal": "PayPal",
    "google": "Google",
    "apple": "Apple",
    "icloud": "iCloud",
    "microsoft": "Microsoft",
    "outlook": "Outlook",
    "instagram": "Instagram",
    "facebook": "Facebook",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "youtube": "YouTube",
    "tiktok": "TikTok",
    "linkedin": "LinkedIn",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "roblox": "Roblox",
    "shopee": "Shopee",
    "dropbox": "Dropbox",
    "wetransfer": "WeTransfer",
    "docusign": "DocuSign",
    "metamask": "MetaMask",
    "coinbase": "Coinbase",
    "binance": "Binance",
    "dhl": "DHL",
    "fedex": "FedEx",
    "usps": "USPS",
    "wellsfargo": "Wells Fargo",
    "santander": "Santander",
    "scotia": "Scotiabank",
    "bancolombia": "Bancolombia",
    "xfinity": "Xfinity",
}

# 브랜드 이름과 정확히 같은 도메인은 이 주소 끝부분일 때만 공식으로 봄
# roblox.com.mu, paypal.top 처럼 끝부분만 바꾼 사칭을 막기 위함
# (go.kr은 정부 기관만 만들 수 있어 공식으로 봄: epost.go.kr)
OFFICIAL_SUFFIXES = {"com", "net", "org", "kr", "co.kr", "go.kr"}

# 나라마다 공식 주소가 있는 브랜드 (google.de, amazon.co.jp 등)
GLOBAL_BRANDS = {"google", "youtube", "amazon", "samsung", "apple", "microsoft", "dhl", "santander", "shopee"}

# 브랜드 이름이 들어가지만 실제 공식인 도메인 (오탐 방지)
OFFICIAL_DOMAINS = {
    "googleapis.com",
    "googleusercontent.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "googleadservices.com",
    "googlevideo.com",
    "youtube-nocookie.com",
    "microsoftonline.com",
    "microsoftonline.us",
    "cdninstagram.com",
    "amazonaws.com",
    "kakaobank.com",
    "kakaopay.com",
    "kakaocorp.com",
    "samsungcard.com",
    "samsunglife.com",
    "samsungfire.com",
    "shinhancard.com",
    "shinhansec.com",
    "scotiabank.com",
    # .com 이 아닌 공식 주소
    "toss.im",
    "naver.me",
    "naver.jp",
    "paypal.me",
    "telegram.me",
    "metamask.io",
    "icloud.com.cn",
    "linkedin.cn",
    "binance.us",
    "dropbox.tech",
}

# 브랜드 이름에 붙어 나오면 사칭으로 볼 단어: paypalsecure, naver-login, webmail-service-xfinity
# applebees, apples 처럼 일반 단어가 붙은 경우는 제외하기 위한 목록
BAIT_WORDS = {
    "login", "signin", "verify", "secure", "security", "account", "update", "password", "bank",
    "support", "service", "help", "center", "auth", "official", "event", "bonus", "gift", "reward",
    "pay", "wallet", "mail", "webmail", "online", "kr", "korea",
}


# 숫자나 비슷한 글자로 바꾼 부분을 원래 글자로 되돌린 버전들
# 예) paypa1 -> paypal, g00gle -> google, sarnsung -> samsung, robiox -> roblox
def lookalike_versions(text: str) -> list:
    base = (
        text.replace("0", "o")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("rn", "m")
    )
    # 1은 l(엘)로도, i(아이)로도 쓰이고, i는 l(엘)처럼 보이므로 모두 확인
    return [base.replace("1", "l"), base.replace("1", "i"), base.replace("1", "l").replace("i", "l")]


# 철자를 살짝 바꾼 오타인지 확인
# apply(apple), never(naver) 같은 실제 단어가 걸리지 않도록
# "아무 글자나 한 글자 바꾸기"는 일부러 제외함
#   "strong" : 피싱에서 흔하고 일반 단어와 거의 안 겹치는 패턴
#   "weak"   : 한 글자 빠뜨림 - samsun(터키 도시), papal(교황의) 같은 실제 단어와 겹칠 수 있음
def typo_kind(part: str, brand: str):

    # 진짜 브랜드 이름이나 복수형(apples)은 오타가 아님
    # usps처럼 짧은 이름은 일반 단어와 겹치기 쉬워 제외 (ussp)
    if part == brand or part == brand + "s" or len(brand) < 5:
        return None

    # 같은 글자 반복: naverr, gooogle
    for i in range(1, len(part)):
        if part[i] == part[i - 1] and part[:i] + part[i + 1:] == brand:
            return "strong"

    # 이웃한 두 글자 순서 바꿈: naevr, googel
    for i in range(len(brand) - 1):
        if brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:] == part:
            return "strong"

    # 한 글자 빠뜨림: gogle, paypl (너무 짧으면 일반 단어일 수 있어 5글자 이상만)
    # 첫 글자를 뺀 경우는 제외: icloud -> cloud 처럼 일반 단어가 되기 쉬움
    if len(part) >= 5:
        for i in range(1, len(brand)):
            if brand[:i] + brand[i + 1:] == part:
                return "weak"

    return None


# 브랜드 이름에 미끼 단어가 붙어 있는지: paypalsecure, securepaypal
def has_bait_word(part: str, brand: str) -> bool:
    return (
        (part.startswith(brand) and part[len(brand):] in BAIT_WORDS)
        or (part.endswith(brand) and part[:-len(brand)] in BAIT_WORDS)
    )


# 공식 도메인인지 확인
# 단, paypal.pages.dev(무료 호스팅)나 paypal.tk(위험 TLD)는 누구나 만들 수 있으므로 공식이 아님
def is_official(ext) -> bool:
    if f"{ext.domain}.{ext.suffix}" in OFFICIAL_DOMAINS:
        return True
    return (
        ext.domain in BRANDS
        and not ext.is_private
        and ext.suffix not in RISKY_TLDS
        and (ext.suffix in OFFICIAL_SUFFIXES or ext.domain in GLOBAL_BRANDS)
    )


# 하나의 브랜드에 대해 사칭 수법을 확인하고 (벌점, 이유)를 반환
# 여러 수법에 해당해도 가장 강한 하나만 반영
def check_brand(brand: str, name: str, sld: str, subdomain: str, path: str):

    # 하이픈으로 나누어서 각각 검사: paypa1-secure-login -> paypa1, secure, login
    parts = sld.split("-")
    joined = sld.replace("-", "")

    # 공식 주소를 서브도메인에 넣어 속이는 경우: naver.com.login-check.xyz
    # (apple.stackexchange.com 같은 정상 사이트와 구분하기 위해 ".co"까지 붙은 경우만)
    if f"{brand}.co" in subdomain:
        return 40, f"{name} 공식 주소처럼 보이게 앞부분을 꾸민 도메인입니다."

    # 브랜드 이름은 그대로인데 주소 끝부분만 다른 경우: roblox.com.mu, paypal.tk, paypal.pages.dev
    if sld == brand:
        return 30, f"{name} 이름을 쓰지만 공식 주소가 아닙니다."

    kinds = {typo_kind(part, brand) for part in parts}

    # 오타로 흉내 낸 경우: naverr, naevr
    if "strong" in kinds:
        return 30, f"{name}의 철자를 살짝 바꾼 도메인입니다."

    # 숫자/비슷한 글자로 흉내 낸 경우: nav3r, paypa1, g00gle, robiox, paypa1secure
    # 하이픈으로 나눈 조각 하나가 바꾸고 나서 브랜드 이름이 될 때만 (appier -> applelr 같은 우연 방지)
    if any(
        v != part and (v == brand or has_bait_word(v, brand))
        for part in parts
        for v in lookalike_versions(part)
    ):
        return 40, f"{name}을 숫자나 비슷한 글자로 흉내 낸 도메인입니다."

    # 한 글자 빠뜨린 경우: gogle (실제 단어와 겹칠 수 있어 약하게)
    if "weak" in kinds:
        return 20, f"{name}에서 한 글자를 뺀 것과 같은 도메인입니다."

    # 브랜드 이름 + 미끼 단어: naver-login, paypalsecure, webmail-service-xfinity
    if (brand in parts and any(p in BAIT_WORDS for p in parts)) or any(has_bait_word(p, brand) for p in parts):
        return 30, f"{name} 이름에 '로그인', '고객센터' 같은 단어를 붙인 도메인입니다."

    # 공식 도메인이 아닌데 브랜드 이름을 쓴 경우: naver-shop, play-roblox
    if brand in parts:
        return 20, f"공식 도메인이 아닌데 {name} 이름을 사용합니다."

    # 브랜드 이름을 하이픈으로 쪼갠 경우: pay-pal-friday
    if brand not in sld and brand in joined:
        return 30, f"{name} 이름을 하이픈으로 쪼개 숨긴 도메인입니다."

    # 다른 단어 사이에 브랜드 이름을 섞은 경우: scotiadevicesecurelogin, soporte-santandermx2026
    # (apple -> pineapple 같은 일반 단어를 피하기 위해 6글자 이상 브랜드만)
    if len(brand) >= 6 and brand in joined:
        return 20, f"도메인 안에 {name} 이름이 섞여 있습니다."

    # 서브도메인에 브랜드 이름: apple.sign-cloud.live, facebookbonus.example.com, verificacionoutlook.freepage.cc
    sub_words = re.split(r"[.-]", subdomain)
    if any(w == brand or has_bait_word(w, brand) or (len(brand) >= 6 and brand in w) for w in sub_words):
        return 20, f"공식 도메인이 아닌데 앞부분에 {name} 이름을 넣었습니다."

    # 주소 경로에 브랜드 이름: example.com/amazon/login.php, xxx.github.io/Netflix-Clone
    if brand in re.split(r"[/._-]", path):
        return 20, f"공식 도메인이 아닌데 주소 경로에 {name} 이름이 있습니다."

    return 0, None


# 브랜드 유사도 분석
def analyze_brand_similarity(url: str) -> dict:

    # login.naverr.com -> subdomain="login", domain="naverr", suffix="com"
    ext = extract_domain(url)

    # 공식 도메인이면 검사하지 않음
    if is_official(ext):
        return {"score": 0, "reasons": []}

    sld = ext.domain.lower()
    subdomain = ext.subdomain.lower()
    path = urlparse(url).path.lower()

    score = 0
    reasons = []

    for brand, name in BRANDS.items():
        brand_score, reason = check_brand(brand, name, sld, subdomain, path)
        if brand_score:
            score += brand_score
            reasons.append(reason)

    # 점수가 너무 커지지 않도록 제한
    score = min(score, 40)

    return {
        "score": score,
        "reasons": reasons
    }
