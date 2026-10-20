import ipaddress
import math
import re
from collections import Counter
import unicodedata
from urllib.parse import unquote, urlparse

import tldextract


# URL에서 "등록된 도메인"을 정확히 뽑아주는 도구
# 예) login.naverr.co.kr -> subdomain="login", domain="naverr", suffix="co.kr"
# suffix_list_urls=() : 인터넷에서 목록을 받지 않고 내장된 목록만 사용 (배포 서버에서도 안정적)
# include_psl_private_domains=True : blogspot.com, pages.dev 같은 무료 호스팅도 "주소 뒷부분"으로 취급
#   -> facebook-login.blogspot.com 에서 사용자가 정한 facebook-login 부분을 검사할 수 있음
extract_domain = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


# 피싱 사이트에서 자주 사용되는 의심 키워드
# 단어의 앞부분만 적어서 변형도 함께 잡음: verif -> verify, verification / secur -> secure, security
SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verif",
    "secur",
    "account",
    "update",
    "password",
    "bank",
    "wallet",
    "confirm",
    "billing",
    "suspend",
    "unlock",
    "recover"
]

# 무료로 발급되어 피싱에 많이 악용된 최상위 도메인(TLD)
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq"}

# 값이 싸서 피싱에 자주 쓰이지만 정상 사이트도 많은 TLD (약하게 반영)
CHEAP_TLDS = {
    "xyz", "top", "live", "icu", "click", "sbs", "cfd", "lol", "site", "online", "help",
    "ink", "host", "vip", "buzz", "rest", "bond", "cyou", "monster", "quest", "support", "delivery"
}

# 내려받으면 바로 실행될 수 있는 파일 확장자 (악성코드 배포에 사용)
DANGEROUS_EXTENSIONS = {
    "exe", "msi", "scr", "bat", "cmd", "ps1", "vbs", "hta", "jar", "dll", "lnk", "sh", "apk"
}

# IoT 기기(공유기, CCTV)를 감염시키는 악성코드가 쓰는 CPU 종류 이름
# 예) manta.mips, kushnet.arm7, x86_64
CPU_ARCH_NAMES = {
    "arm", "arm4", "arm4l", "arm4tl", "arm5", "arm6", "arm7", "armv6l", "armv7l", "aarch64",
    "mips", "mpsl", "mipsel", "m68k", "ppc", "ppc440", "sh4", "spc", "sparc",
    "x86", "x86_64", "i686", "i586", "arc"
}

# 악성코드를 감싸서 배포할 때 쓰는 압축/디스크 이미지 파일
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso"}

# 누구나 무료로 홈페이지를 만들 수 있는 곳
# 최신 피싱 대부분이 여기에 xxx.vercel.app 같은 이름으로 올라옴
FREE_HOSTING = {
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "replit.app", "github.io", "gitlab.io",
    "blogspot.com", "web.app", "firebaseapp.com", "glitch.me", "onrender.com", "herokuapp.com",
    "weebly.com", "wixsite.com", "webflow.io", "square.site", "godaddysites.com", "notion.site",
    "framer.website", "framer.app", "bolt.host", "craftum.io", "freepage.cc", "000webhostapp.com", "mybluehost.me",
    "sites.google.com", "storage.googleapis.com", "amazonaws.com", "r2.dev", "backblazeb2.com", "myqcloud.com",
}

# 인기 사이트지만 누구나 내용을 올릴 수 있어 악용되는 곳 (무료 호스팅 포함)
USER_CONTENT_PLATFORMS = FREE_HOSTING | {
    # URL 단축
    "bit.ly", "tinyurl.com", "rebrand.ly", "goo.su", "t.co", "is.gd", "cutt.ly",
    "naver.me", "me2.do", "han.gl", "url.kr",
    # 코드 저장소
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    # 파일 공유 / 클라우드
    "drive.google.com", "docs.google.com", "forms.gle",
    "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
    "mediafire.com", "mega.nz", "cdn.discordapp.com",
    "contabostorage.com", "contaboserver.net",
    # 붙여넣기 사이트
    "pastebin.com", "paste.ee",
}

# 주소 앞부분에 단어로 넣으면 다른 주소처럼 보이게 하는 TLD 단어
EMBEDDED_TLD_WORDS = {"com", "net", "org", "gov", "edu"}

# 주소 안에 들어 있는 이메일 주소: 피싱 페이지가 피해자 이메일을 미리 채워 넣는 수법
# 예) ...pages.dev/#victim@company.com
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.IGNORECASE)


# 주소(host)가 목록의 사이트이거나 그 서브도메인인지 확인
# (raw.githubusercontent.com -> githubusercontent.com)
def host_in(host: str, sites: set) -> bool:
    return any(host == s or host.endswith("." + s) for s in sites)


# 누구나 파일을 올릴 수 있는 사이트의 주소인지 확인
def is_user_content_platform(host: str) -> bool:
    return host_in(host, USER_CONTENT_PLATFORMS)


# 사람이 지은 이름이 아니라 자동으로 만든 것 같은 이름인지
# 예) nmtp49wkoa, np7gesfzfdeq4j705h275 (8글자 이상에서 숫자와 글자가 두 번 이상 번갈아 나옴)
# microsoft365, shop2024 처럼 끝에만 숫자가 붙은 이름은 제외
def looks_random(word: str) -> bool:
    if len(word) < 8:
        return False
    switches = sum(a.isdigit() != b.isdigit() for a, b in zip(word, word[1:]))
    return switches >= 2


# 글자가 얼마나 무작위로 섞여 있는지 (섀넌 엔트로피, 클수록 무작위)
# 예) google 1.9, coupang 2.8, wbeuvipfx75 3.5
def entropy(text: str) -> float:
    return -sum(c / len(text) * math.log2(c / len(text)) for c in Counter(text).values())


# 다른 나라 글자로 영어를 흉내 낸 주소인지 (аpple.com: 첫 글자가 러시아어 а)
# 영어 글자와 러시아어/그리스어 글자가 한 이름 안에 섞여 있으면 흉내로 봄
# 태국어, 한글처럼 자기 나라 글자만 쓴 정상 도메인(한국.com)은 제외
def is_homograph(host: str) -> bool:
    for label in host.split("."):
        if not label.startswith("xn--"):
            continue
        try:
            text = label.encode().decode("idna")
        except UnicodeError:
            continue
        has_latin = any("a" <= c <= "z" for c in text)
        has_lookalike = any(unicodedata.name(c, "").startswith(("CYRILLIC", "GREEK")) for c in text)
        if has_latin and has_lookalike:
            return True
    return False


# URL 자체의 특징을 분석하는 함수
def analyze_url_structure(url: str):

    # 위험 점수
    score = 0

    # 위험하다고 판단한 이유를 저장할 리스트
    reasons = []

    # 대소문자 구분 없이 검사하기 위해 소문자로 변환
    lower_url = url.lower()

    # URL에서 도메인 부분 추출
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # 1. 의심 키워드 검사
    # 은행/로그인 페이지 같은 정상 사이트도 키워드를 쓰므로 최대 20점까지만 반영
    keyword_score = 0
    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            keyword_score += 10
            reasons.append(f"의심 키워드 포함: {word}")
    score += min(keyword_score, 20)

    # 2. URL 길이 검사
    if len(url) > 75:
        score += 10
        reasons.append("URL이 비정상적으로 깁니다.")

    # 3. 하이픈 개수 검사 (my-cool-site.com 같은 정상 도메인을 위해 3개 이상만)
    hyphen_count = domain.count("-")

    if hyphen_count >= 3:
        score += 10
        reasons.append("도메인에 하이픈이 여러 개 포함되어 있습니다.")

    # 4. @ 속임수 검사
    # http://naver.com@evil.com 은 실제로 evil.com 에 접속됨
    if "@" in domain:
        score += 40
        reasons.append("주소에 @가 있어 실제로 접속되는 사이트를 숨기고 있습니다.")

    # 5. 위험 TLD 검사
    ext = extract_domain(url)
    tld = ext.suffix
    if tld in RISKY_TLDS:
        score += 15
        reasons.append(f"피싱에 자주 악용되는 도메인(.{tld})을 사용합니다.")
    elif tld in CHEAP_TLDS:
        score += 10
        reasons.append(f"피싱에 자주 쓰이는 저가 도메인(.{tld})을 사용합니다.")

    # 6. 도메인 대신 IP 주소를 쓰는지 검사
    # 192.168.0.1 같은 내부망 주소(공유기 설정 QR 등)는 정상이므로 제외
    try:
        ip = ipaddress.ip_address(parsed_url.hostname or "")
        if ip.is_global:
            score += 40
            reasons.append("도메인 대신 IP 주소로 된 사이트입니다.")
    except ValueError:
        pass

    # 7. 일반적이지 않은 포트 번호 검사 (예: :40499)
    try:
        port = parsed_url.port
    except ValueError:
        port = None
    if port not in (None, 80, 443):
        score += 10
        reasons.append(f"일반적이지 않은 포트({port})를 사용합니다.")

    # 8. 실행 파일 다운로드 검사
    # 경로의 마지막 부분: /bin/manta.mips -> manta.mips
    filename = parsed_url.path.rsplit("/", 1)[-1].lower()
    extension = filename.rsplit(".", 1)[-1] if "." in filename else ""

    if extension in DANGEROUS_EXTENSIONS:
        score += 30
        reasons.append(f"실행 파일(.{extension})을 내려받게 합니다.")
    elif extension in CPU_ARCH_NAMES or filename in CPU_ARCH_NAMES:
        score += 40
        reasons.append("IoT 기기를 노리는 악성코드 파일 이름입니다.")

    # 9. 누구나 파일을 올릴 수 있는 사이트에서 압축 파일을 바로 내려받게 하는지 검사
    # SmartLoader: 가짜 GitHub 저장소에 악성 zip을 올리고 raw 주소로 배포
    # 예) raw.githubusercontent.com/user/repo/main/Tool-v2.6.zip
    #     github.com/user/repo/raw/refs/heads/main/Tool-v2.5.zip
    host = (parsed_url.hostname or "").lower()
    if extension in ARCHIVE_EXTENSIONS and is_user_content_platform(host):
        if host == "raw.githubusercontent.com" or "/raw/" in parsed_url.path:
            score += 40
            reasons.append(f"코드 저장소에 올린 압축 파일(.{extension})을 직접 내려받게 합니다.")
        else:
            score += 30
            reasons.append(f"누구나 파일을 올릴 수 있는 사이트에서 압축 파일(.{extension})을 내려받게 합니다.")

    # 10. 무료 호스팅 검사
    # 정상 개인 사이트도 많아서 이것만으로는 safe, 다른 단서와 겹치면 warning
    if host_in(host, FREE_HOSTING):
        score += 15
        reasons.append("누구나 무료로 만들 수 있는 호스팅 주소입니다.")

    # 11. 자동으로 만든 것 같은 이름 검사 (nmtp49wkoa-h05a.vercel.app)
    # (xn--3e0b707e 같은 한글/외국어 도메인의 변환된 이름은 제외)
    labels = [label for label in f"{ext.subdomain}.{ext.domain}".split(".") if not label.startswith("xn--")]
    names = [name for label in labels for name in label.split("-")]
    if any(looks_random(name) for name in names):
        score += 15
        reasons.append("숫자와 글자가 무작위로 섞인 주소입니다.")

    # 도메인 이름 부분 (IP 주소는 6번에서 따로 검사, xn-- 로 시작하는 다국어 도메인은 제외)
    name = ext.domain.lower() if ext.suffix else ""
    if name.startswith("xn--"):
        name = ""

    # 11-1. 무료 호스팅 + 무작위 글자 이름 (Tran & Sovilj 2024 엔트로피 특징)
    # 모든 주소에 적용하면 google-analytics.com 같은 긴 정상 도메인이 걸려서 무료 호스팅에만 적용
    # (측정: 새 피싱 450개 탐지율 +9.3%p, 정상 1만 개 오탐 변화 0)
    if host_in(host, FREE_HOSTING) and len(name) >= 8 and entropy(name) >= 3.3:
        score += 15
        reasons.append("무료 호스팅 주소의 이름이 무작위 글자로 되어 있습니다.")

    # 11-2. 도메인 숫자 비율 (Tran & Sovilj 2024 특징 중요도 2위)
    if len(name) >= 6 and sum(c.isdigit() for c in name) / len(name) >= 0.3:
        score += 10
        reasons.append("도메인 이름에 숫자가 비정상적으로 많습니다.")

    # 11-3. 비정상적으로 긴 도메인 이름 (Tran & Sovilj 2024 특징 중요도 7위 "도메인 길이")
    # 20자는 samsungcloudsolution.com 같은 정상 도메인이 걸려서 25자부터
    if len(name) >= 25:
        score += 10
        reasons.append("도메인 이름이 비정상적으로 깁니다.")

    # 11-4. 주소 안에 다른 주소 끝(.com, gov 등)을 단어로 넣은 경우 (Tran & Sovilj 2024 "URL 안 TLD 개수")
    # 예) info-hacienda-gov.weebly.com, customer-mail-com.weebly.com
    # (kr, app, io 등은 정상 국내/서비스 도메인에도 흔해서 제외)
    name_words = re.split(r"[.-]", f"{ext.subdomain}.{name}".lower())
    if any(w in EMBEDDED_TLD_WORDS for w in name_words):
        score += 15
        reasons.append("주소 앞부분에 다른 주소(.com, gov 등)처럼 보이는 단어를 넣었습니다.")

    # 11-5. 서브도메인 깊이 (Arpita 2026 XPhishNet 핵심 판별 지표)
    # 예) login.my.gov.au-taxpayer.de5.net (www 제외)
    if len([s for s in ext.subdomain.split(".") if s and s != "www"]) >= 3:
        score += 10
        reasons.append("주소 앞부분이 여러 단계로 깊게 이어져 있습니다.")

    # 12. 다른 나라 글자로 영어 주소를 흉내 냈는지 검사
    if is_homograph(host):
        score += 30
        reasons.append("다른 나라 글자로 영어 주소를 흉내 냈을 수 있는 주소입니다.")

    # 13. 주소 안에 이메일이 들어 있는지 검사
    rest = unquote(f"{parsed_url.path}?{parsed_url.query}#{parsed_url.fragment}")
    if EMAIL_PATTERN.search(rest):
        score += 20
        reasons.append("주소 안에 이메일 주소가 들어 있습니다. 피싱 페이지가 피해자 이메일을 미리 채울 때 쓰는 수법입니다.")

    # 분석 결과 반환
    return {
        "score": score,
        "domain": domain,
        "reasons": reasons
    }
