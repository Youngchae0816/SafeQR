# 페이지 내용 분석
# QR 주소에 서버가 직접 접속해서 HTML(페이지 소스)만 받아 읽어 보는 모듈
# 스크립트는 실행하지 않고, 받은 글자만 검사함

import http.client
import ipaddress
import re
import socket
import ssl
import time
from html import unescape
from urllib.parse import urljoin, urlparse

from services.url_analyzer import (
    ARCHIVE_EXTENSIONS, CPU_ARCH_NAMES, DANGEROUS_EXTENSIONS,
    analyze_url_structure, extract_domain, is_user_content_platform,
)
from services.brand_similarity import BRANDS, analyze_brand_similarity, is_official


# 한 번 접속에 기다리는 최대 시간(초)
TIMEOUT = 4

# 리다이렉트를 여러 번 따라가도 전체적으로 이 시간(초)이 지나면 중단
TOTAL_TIMEOUT = 8

# 리다이렉트(다른 주소로 이동)를 따라가는 최대 횟수
MAX_REDIRECTS = 5

# HTML은 앞부분 1MB까지만 읽음 (큰 파일로 서버를 괴롭히는 것 방지)
MAX_BYTES = 1_000_000

# 휴대폰 브라우저인 척 접속 (피싱 사이트는 봇이나 PC에는 정상 페이지를 보여주기도 함)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; SM-S921N) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
}

# 페이지 제목/본문에서 찾을 브랜드의 한글 이름
KOREAN_NAMES = {
    "naver": "네이버", "kakao": "카카오", "samsung": "삼성", "google": "구글", "apple": "애플",
    "microsoft": "마이크로소프트", "instagram": "인스타그램", "facebook": "페이스북",
    "youtube": "유튜브", "paypal": "페이팔", "amazon": "아마존", "netflix": "넷플릭스",
    "kbstar": "국민은행", "wooribank": "우리은행", "hanabank": "하나은행", "nonghyup": "농협",
    "epost": "우체국", "cjlogistics": "대한통운",
}

# 훔친 정보를 바로 빼돌리는 곳 (피싱 키트가 많이 씀)
EXFIL_PATTERNS = ["api.telegram.org/bot", "discord.com/api/webhooks", "discordapp.com/api/webhooks"]

# 정상 사이트에 흔한 SNS 링크 (없으면 급조된 페이지일 가능성)
SOCIAL_LINKS = ("facebook.com/", "instagram.com/", "twitter.com/", "x.com/", "linkedin.com/", "youtube.com/",
                "tiktok.com/", "pinterest.com/", "blog.naver.com/", "pf.kakao.com/", "t.me/", "discord.gg/")

# 봇 차단 페이지 제목 (서버 접속이 막혀 진짜 내용이 아닌 차단 화면을 받은 경우)
CHALLENGE_TITLES = ("attention required! | cloudflare", "just a moment...", "access denied", "403 forbidden", "ddos-guard")

# 단축 서비스가 이미 위험 링크로 막아 두고 보여주는 경고 화면
SHORTENER_BLOCK_TITLES = ("warning! | there might be a problem with the requested link",  # bit.ly
                          "warning! | the account that created this link")              # bit.ly
SHORTENER_BLOCK_URLS = ("tinyurl.com/app/nospam/",)

# 코드를 숨길 때 쓰는 자바스크립트 함수
OBFUSCATION_PATTERNS = ["eval(", "atob(", "unescape(", "fromcharcode(", "document.write("]


# ---------------------------------------------------------------------------
# 1. 안전하게 접속하기 (서버 내부 공격 SSRF 방어)
# ---------------------------------------------------------------------------
# 누군가 QR에 http://127.0.0.1 이나 http://169.254.169.254(클라우드 서버 설정 정보) 같은
# 내부 주소를 넣으면, 우리 서버가 자기 내부에 접속해 버릴 수 있음.
# 그래서 접속 전에 주소가 가리키는 IP를 직접 확인하고, 공개 인터넷 IP일 때만 접속함.
# 확인한 IP로만 접속하므로, 확인 후에 DNS 답을 바꾸는 속임수(DNS rebinding)도 통하지 않음.

class BlockedAddress(Exception):
    pass


# 주소를 IP로 바꾸고, 모든 IP가 공개 인터넷 주소일 때만 그중 하나를 반환
def resolve_public_ip(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    ips = {info[4][0] for info in infos}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or addr.is_multicast:
            raise BlockedAddress(f"내부망 주소라 접속하지 않음: {host} -> {ip}")
    return sorted(ips)[0]


# 미리 확인한 IP로만 접속하는 연결 (http / https)
class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, **kwargs)
        self.ip = ip

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kwargs):
        super().__init__(host, context=ssl.create_default_context(), **kwargs)
        self.ip = ip

    def connect(self):
        sock = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# HTML의 <meta http-equiv="refresh" content="0;url=..."> 이동 주소
META_REFRESH = re.compile(
    r"<meta[^>]+http-equiv=[\"']?refresh[^>]+url\s*=\s*['\"]?([^'\" >]+)", re.IGNORECASE
)


# 주소에 접속해서 최종 주소, 이동 경로, HTML, 인증서 정보를 반환
# HTML이 아닌 파일이면 html=None (내려받기만 하고 절대 실행하지 않음)
def fetch_page(url: str) -> dict:

    deadline = time.monotonic() + TOTAL_TIMEOUT
    chain = [url]

    def result(html=None, content_type=None, cert=None, cert_error=None):
        return {"final_url": url, "chain": chain, "html": html, "content_type": content_type,
                "cert": cert, "cert_error": cert_error}

    for _ in range(MAX_REDIRECTS + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("페이지 접속 시간 초과")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise BlockedAddress(f"웹 주소가 아님: {url}")

        https = parsed.scheme == "https"
        port = parsed.port or (443 if https else 80)
        ip = resolve_public_ip(parsed.hostname, port)

        connection_class = PinnedHTTPSConnection if https else PinnedHTTPConnection
        conn = connection_class(parsed.hostname, ip, port=port, timeout=min(TIMEOUT, remaining))
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

        try:
            conn.request("GET", path, headers=HEADERS)
            response = conn.getresponse()

            # 리다이렉트: 다음 주소로 이동 (다음 반복에서 다시 IP 확인)
            location = response.getheader("Location")
            if response.status in (301, 302, 303, 307, 308) and location:
                url = urljoin(url, location)
                chain.append(url)
                continue

            # HTTPS 인증서 정보 (연결이 열려 있을 때만 읽을 수 있음)
            cert = conn.sock.getpeercert() if https else None

            content_type = response.getheader("Content-Type", "").lower()
            if "html" not in content_type:
                return result(content_type=content_type, cert=cert)

            body = response.read(MAX_BYTES)

        # 인증서가 가짜이거나 만료된 사이트 (브라우저도 경고 화면을 띄움)
        except ssl.SSLCertVerificationError as e:
            return result(cert_error=e.verify_message)
        finally:
            conn.close()

        html = decode_html(body, content_type)

        # 페이지 안에서 다른 주소로 바로 넘기는 경우도 따라감
        refresh = META_REFRESH.search(html)
        if refresh:
            url = urljoin(url, refresh.group(1))
            chain.append(url)
            continue

        return result(html=html, content_type=content_type, cert=cert)

    raise BlockedAddress("리다이렉트가 너무 많음")


# 글자 인코딩(utf-8, euc-kr 등)을 찾아서 HTML 글자로 변환
def decode_html(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=[\"']?([\w-]+)", content_type) or \
        re.search(rb"charset=[\"']?([\w-]+)", body[:2048])
    charset = match.group(1) if match else "utf-8"
    if isinstance(charset, bytes):
        charset = charset.decode()
    try:
        return body.decode(charset, errors="ignore")
    except LookupError:
        return body.decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# 2. HTML 내용 검사
# ---------------------------------------------------------------------------

# login.example.co.kr -> example.co.kr (도메인 이름이 없으면 빈 문자열)
def registered_domain(url: str) -> str:
    ext = extract_domain(url)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else ""


# 페이지 제목과 본문에 나오는 브랜드 찾기
def find_brands(text: str) -> list:
    found = []
    for key, name in BRANDS.items():
        names = {key, name.lower(), KOREAN_NAMES.get(key, key)}
        # 3글자 이하 영어 이름(dhl 등)은 다른 단어 속에 우연히 들어가기 쉬워 단어 단위로만
        if any(re.search(rf"(?<![a-z]){re.escape(n)}(?![a-z])", text) for n in names):
            found.append(name)
    return found


# 받은 HTML에서 피싱 단서 찾기
def inspect_html(html: str, page_url: str) -> tuple:
    score = 0
    reasons = []

    lower = html.lower()
    official = is_official(extract_domain(page_url))

    title_match = re.search(r"<title[^>]*>(.*?)</title>", lower, re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    has_password = re.search(r"type\s*=\s*[\"']?password", lower) is not None

    # 1) 브랜드 로그인 화면 흉내: 공식이 아닌데 제목에 브랜드 + 비밀번호 입력창
    title_brands = find_brands(title)
    if has_password and title_brands and not official:
        score += 40
        reasons.append(f"공식 사이트가 아닌데 {', '.join(title_brands)} 로그인 화면처럼 꾸몄습니다.")
    elif has_password and not official:
        score += 10
        reasons.append("비밀번호를 입력받는 페이지입니다.")

    # 2) 입력한 정보를 텔레그램/디스코드로 바로 보냄
    if any(p in lower for p in EXFIL_PATTERNS):
        score += 30
        reasons.append("입력한 정보를 텔레그램이나 디스코드로 몰래 보내는 코드가 있습니다.")

    # 3) 비밀번호 입력 폼이 전혀 다른 사이트로 전송됨
    if has_password:
        page_domain = registered_domain(page_url)
        for action in re.findall(r"<form[^>]+action\s*=\s*[\"']([^\"']+)", lower):
            target = registered_domain(urljoin(page_url, action))
            if target and target != page_domain:
                score += 20
                reasons.append(f"입력한 정보를 다른 사이트({target})로 보냅니다.")
                break

    # 4) 사이트 운영 흔적 없이 입력만 받는 페이지 (Chibueze 2026 특징 중요도 1~4위)
    # 정상 사이트는 SNS 링크·저작권 표시·메타 설명을 갖추지만 급조된 피싱 페이지는 빠뜨림
    # 측정: 셋 다 없는 비율 피싱 54% / 정상 20%, 입력 버튼까지 있으면 정상 오탐 0 (새 피싱 450개 +8)
    hrefs = re.findall(r"<a[^>]+href\s*=\s*[\"']([^\"']*)", lower)
    has_social = any(s in h for h in hrefs for s in SOCIAL_LINKS)
    has_copyright = "©" in html or "&copy;" in lower or "copyright" in lower
    has_description = re.search(r"<meta[^>]+name\s*=\s*[\"']description[\"']", lower) is not None
    has_submit = re.search(r"type\s*=\s*[\"']?submit|<button", lower) is not None
    if has_submit and not (has_social or has_copyright or has_description):
        score += 15
        reasons.append("SNS 링크, 저작권 표시, 사이트 설명 없이 입력 버튼만 있는 페이지입니다.")

    # 5) 내용은 거의 없고 숨겨진 코드만 있음
    visible_text = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", lower, flags=re.DOTALL)
    if len(visible_text.split()) < 30 and any(p in lower for p in OBFUSCATION_PATTERNS):
        score += 20
        reasons.append("내용 없이 내용을 숨기는 코드만 있는 페이지입니다.")

    return score, reasons


# 페이지 안 링크(<a href>) 개수 (javascript:, mailto:, tel: 제외)
# 측정: 피싱 페이지 중앙값 2개, 정상 사이트 37개
def count_links(html: str) -> int:
    links = re.findall(r"<a[^>]+href\s*=\s*[\"']([^\"'#]+)", html.lower())
    return sum(not l.startswith(("javascript:", "mailto:", "tel:")) for l in links)


# robots.txt(검색 엔진 안내 파일)가 있는지 (Tran & Sovilj 2024: sitemap 개수 중요도 5위)
# 측정: 정상 사이트 81%가 있고, 피싱 사이트는 48%만 있음
# True/False, 확인하지 못하면 None
def has_robots_txt(page_url: str):
    p = urlparse(page_url)
    url = f"{p.scheme}://{p.netloc}/robots.txt"
    try:
        for _ in range(2):  # http -> https 같은 이동 1번까지
            p = urlparse(url)
            https = p.scheme == "https"
            port = p.port or (443 if https else 80)
            ip = resolve_public_ip(p.hostname, port)   # 내부망 차단 동일하게 적용
            conn = (PinnedHTTPSConnection if https else PinnedHTTPConnection)(p.hostname, ip, port=port, timeout=TIMEOUT)
            try:
                conn.request("GET", p.path, headers=HEADERS)
                response = conn.getresponse()
                location = response.getheader("Location")
                if response.status in (301, 302, 307, 308) and location:
                    url = urljoin(url, location)
                    continue
                if response.status != 200:
                    return False
                return "user-agent" in response.read(100_000).decode(errors="ignore").lower()
            finally:
                conn.close()
        return False
    except Exception:
        return None


# 접속하면 악성 파일을 받게 될 수 있는 주소인지 (IP 주소, 실행 파일, 압축 파일, IoT 악성코드 파일명)
def is_risky_download(url: str) -> bool:
    parsed = urlparse(url)
    try:
        ipaddress.ip_address(parsed.hostname or "")
        return True
    except ValueError:
        pass
    filename = parsed.path.rsplit("/", 1)[-1].lower()
    extension = filename.rsplit(".", 1)[-1] if "." in filename else ""
    return extension in DANGEROUS_EXTENSIONS | ARCHIVE_EXTENSIONS | CPU_ARCH_NAMES or filename in CPU_ARCH_NAMES


# 빈약한 페이지 규칙: 링크 3개 미만 + robots.txt 없음 + 도메인이 1년 미만이거나 나이 확인 안 됨 -> +15점
# 피싱 키트는 로그인 화면 하나만 있고 검색 엔진 설정이 없음
# wordpress.com, weibo.com 같은 오래된 대형 사이트는 봇에게 빈 페이지를 주기도 해서 1년 이상 된 도메인은 제외
# (측정: 새 피싱 450개 중 +10개 탐지, 정상 844개 오탐 0)
# 도메인 나이(WHOIS)는 페이지 분석과 동시에 실행되므로 둘 다 끝난 뒤 main.py에서 호출
def apply_sparse_page_rule(page, domain_trust):
    if not page or not page.pop("sparse_page", False):
        return
    if domain_trust and domain_trust["domain_age_days"] >= 365:
        return
    page["score"] = min(page["score"] + 15, 100)
    page["reasons"].append("링크가 거의 없고 검색 엔진 설정(robots.txt)도 없는, 급조된 것 같은 페이지입니다.")


# ---------------------------------------------------------------------------
# 3. 사용자에게 보여줄 사이트 정보 (메타데이터)
# ---------------------------------------------------------------------------
# 주의: 제목/설명은 사이트가 "스스로 밝힌" 내용이라 피싱도 "네이버 로그인"이라고 씀
# 앱에서는 실제 주소(final_url)와 나란히 보여줘서 비교할 수 있게 해야 함

# <meta property="og:title" content="..."> 같은 값 꺼내기
def meta_content(html: str, name: str):
    for pattern in (
        rf"<meta[^>]+(?:property|name)\s*=\s*[\"']{name}[\"'][^>]*content\s*=\s*[\"']([^\"']*)",
        rf"<meta[^>]+content\s*=\s*[\"']([^\"']*)[\"'][^>]*(?:property|name)\s*=\s*[\"']{name}[\"']",
    ):
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return clean_text(match.group(1))
    return None


# HTML 기호(&amp; 등)를 글자로 바꾸고 너무 길면 자름
def clean_text(text: str, limit: int = 200):
    text = " ".join(unescape(text).split())
    return text[:limit] or None


def page_title(html):
    title = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    return (clean_text(title.group(1)) or "").lower() if title else ""


def is_challenge_page(html):
    return page_title(html).startswith(CHALLENGE_TITLES)


def is_shortener_block(html, final_url):
    return page_title(html).startswith(SHORTENER_BLOCK_TITLES) or any(p in final_url for p in SHORTENER_BLOCK_URLS)


# 인증서에서 발급기관과 발급일 꺼내기
def certificate_info(cert):
    if not cert:
        return None
    issuer = dict(item[0] for item in cert.get("issuer", ()))
    issued = ssl.cert_time_to_seconds(cert["notBefore"])
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    return {
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "issued_at": time.strftime("%Y-%m-%d", time.gmtime(issued)),
        "expires_at": time.strftime("%Y-%m-%d", time.gmtime(expires)),
        "age_days": int((time.time() - issued) // 86400),
    }


def extract_metadata(page: dict) -> dict:
    html = page["html"] or ""
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return {
        "final_url": page["final_url"],
        "redirect_chain": page["chain"],
        "content_type": (page["content_type"] or "").split(";")[0] or None,
        "title": meta_content(html, "og:title") or (clean_text(title.group(1)) if title else None),
        "description": meta_content(html, "og:description") or meta_content(html, "description"),
        "site_name": meta_content(html, "og:site_name"),
        "has_password_input": re.search(r"type\s*=\s*[\"']?password", html, re.IGNORECASE) is not None,
        "https": page["final_url"].startswith("https://"),
        "certificate": certificate_info(page["cert"]),
        "certificate_error": page["cert_error"],
    }


# ---------------------------------------------------------------------------
# 4. 전체 페이지 분석
# ---------------------------------------------------------------------------

def analyze_page(url: str):

    # IP 주소, 실행 파일, 압축 파일 주소는 접속하지 않음 (Rafsanjani 2024: 악성 파일 다운로드 방지)
    # 이런 주소는 URL 분석만으로 이미 높은 점수를 받음
    if is_risky_download(url):
        return {"score": 0, "final_url": url, "reasons": [], "metadata": None, "sparse_page": False}

    # 접속 실패, 내부망 주소 차단 등은 이 검사만 빼고 분석 계속
    try:
        page = fetch_page(url)
    except BlockedAddress as e:
        print(f"페이지 접속 차단: {e}")
        return None
    except Exception as e:
        print(f"페이지 접속 실패 ({url}): {e}")
        return None

    # 봇 차단 화면을 받았으면 진짜 페이지를 못 본 것이므로 접속 실패와 똑같이 처리
    # (차단 화면에는 버튼만 있고 SNS·저작권이 없어서 정상 사이트도 "급조된 페이지"로 오해함)
    if is_challenge_page(page["html"]):
        print(f"봇 차단 페이지 ({url})")
        return None

    score = 0
    reasons = []
    final_url = page["final_url"]

    # 단축 URL처럼 누구나 만들 수 있는 주소에서 다른 사이트로 이동했다면 최종 도착 주소도 다시 분석
    # 예) surl.li/abc -> evil-site.xyz/login
    # (gmail.com -> accounts.google.com 같은 정상 이동은 제외하기 위해 단축 URL 등에서 출발한 경우만)
    # 원래 주소보다 점수가 높아진 만큼만 더함 (같은 이유로 두 번 벌점 주지 않기)
    host = (urlparse(url).hostname or "").lower()

    # 단축 서비스가 이미 위험 링크로 차단했으면 진짜 목적지를 볼 수 없으므로 그 판정을 그대로 씀
    if is_user_content_platform(host) and is_shortener_block(page["html"], final_url):
        score += 60
        reasons.append("단축 URL 서비스가 이미 위험한 링크로 차단했습니다.")

    if is_user_content_platform(host) and registered_domain(final_url) != registered_domain(url):
        before = analyze_url_structure(url)["score"] + analyze_brand_similarity(url)["score"]
        lexical = analyze_url_structure(final_url)
        brand = analyze_brand_similarity(final_url)
        extra = lexical["score"] + brand["score"] - before
        if extra > 0:
            score += extra
            reasons += [f"최종 도착 주소({lexical['domain']}): {r}" for r in lexical["reasons"] + brand["reasons"]]

    if page["cert_error"]:
        score += 20
        reasons.append("HTTPS 인증서가 올바르지 않습니다. 브라우저도 경고하는 사이트입니다.")

    link_count = robots = None
    if page["html"]:
        html_score, html_reasons = inspect_html(page["html"], final_url)
        score += html_score
        reasons += html_reasons

        # robots.txt는 링크가 적은 페이지일 때만 확인 (요청 1번 추가)
        link_count = count_links(page["html"])
        if link_count < 3:
            robots = has_robots_txt(final_url)

    metadata = extract_metadata(page)
    metadata["link_count"] = link_count
    metadata["has_robots_txt"] = robots

    return {
        "score": min(score, 100),
        "final_url": final_url,
        "reasons": reasons,
        "metadata": metadata,
        "sparse_page": link_count is not None and link_count < 3 and robots is False,
    }
