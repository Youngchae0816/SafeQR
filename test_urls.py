# 오탐/미탐 확인용 테스트 (외부 API는 호출하지 않음)
# 실행: python test_urls.py

from services.url_analyzer import analyze_url_structure
from services.brand_similarity import analyze_brand_similarity
from services.risk_scorer import calculate_risk


# 정상 사이트: 반드시 safe 가 나와야 함
SAFE_URLS = [
    "https://www.naver.com",
    "https://m.naver.com",
    "https://nid.naver.com/nidlogin.login",
    "https://accounts.google.com/signin/v2/identifier",
    "https://www.google.co.kr",
    "https://www.paypal.com/signin",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&redirect_uri=https://example.com",
    "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    "https://accounts.kakao.com/login?continue=https%3A%2F%2Faccounts.kakao.com",
    "https://www.kakaobank.com/login",
    "https://apple.stackexchange.com",
    "https://www.applebees.com",
    "https://www.pineapple-recipes-blog.com",
    "https://never-ending-story.com",
    "https://apply-online.kr",
    "https://stackoverflow.com",
    "https://github.com/login",
    "https://github.com/python/cpython",
    "https://github.com/python/cpython/blob/main/README.rst",
    "https://raw.githubusercontent.com/python/cpython/main/README.rst",
    "https://www.youtube.com/watch?v=abc",
    "https://www.samsungcard.com",
    "https://apples-and-oranges.com",
    "https://papal-visit-news.com",
    "https://samsun-hotel.com",
    "http://192.168.0.1",
    "https://abc.github.io/project",
    "https://mirror.kakao.com/centos/9-stream/BaseOS/x86_64/os/",
    # QR에서 자주 보는 정상 주소
    "https://toss.im/event/benefit",
    "https://www.epost.go.kr/main.retrieveMainPage.comm",
    "https://www.coupang.com/vp/products/7334651263?itemId=18768397553",
    "https://smartstore.naver.com/mycafe/products/5123456789",
    "https://blog.naver.com/mycafe/223456789012",
    "https://www.instagram.com/mycafe_seoul/",
    "https://docs.google.com/forms/d/e/1FAIpQLSf3kXyZ8abc/viewform",
    "https://forms.gle/a1B2c3D4e5F6",
    "https://order.my-cafe.com/menu?table=3",
    "https://my-portfolio.vercel.app",
    "https://naver.me/5abcDEF1",
    "https://pf.kakao.com/_xabcd/chat",
    "https://www.kbstar.com",
    "https://www.shinhan.com/index.jsp",
    "https://www.youtube.com/@mycafe",
    "https://xn--3e0b707e.com",
]

# 피싱 의심: warning 이상이 나와야 함
RISKY_URLS = [
    "http://naverr.com",
    "http://nav3r.com",
    "http://naevr.com",
    "http://naver-login.com",
    "http://login.naverr.com",
    "http://naverr-login-secure.com",
    "http://www.nav3r-account-verify.com/login?update=password",
    "http://paypa1-secure-verify.tk/login?redirect=account",
    "http://paypalsecure.com",
    "http://g00gle.com",
    "http://gooogle-account.com",
    "http://sarnsung.com",
    "http://naver.com@evil-site.xyz/login",
    "http://naver.com.login-check.xyz",
    "http://paypal.tk",
    "http://facebook-login-login.blogspot.com/?m=1",
    # 최신 피싱 수법 (OpenPhish 실제 사례)
    "http://roblox.com.mu/communities/1597305904/NaowiiiClothes",
    "https://www.robiox.com.gr/users/4774313649/profile",
    "https://instagram-itng.vercel.app/",
    "https://apple.sign-cloud.live/help?9jp",
    "https://nmtp49wkoa-h05a.vercel.app/",
    "https://security-server-static-page--grantyourwishca.replit.app/#arispro@adf499553cd1947c7f4786bc8a57f15e03a8.net",
    "https://www.scotiadevicesecurelogin.com/oauth",
    "https://pay-pal-friday.net/",
    "https://mmilegal.co.za/public/amazon/login.php",
    "http://xn--pple-43d.com",
    # 악성코드 배포 (URLhaus 실제 사례)
    "http://42.5.9.216:40499/bin.sh",
    "http://115.62.145.147:34979/i",
    "http://c2.teamzeroday.net/bin/manta.arc",
    "http://185.166.153.194/clip.exe",
    "http://94.154.43.100/eclipse/bin/eclipse.apk",
    # SmartLoader - 가짜 GitHub 저장소의 zip (URLhaus 실제 사례)
    "https://raw.githubusercontent.com/the-vishal-gupta/Question_Answering-_System/main/saasenv/Include/site/python3.12/greenlet/System_Question_Answering_v2.1.zip",
    "https://raw.githubusercontent.com/Jts36/LanguageModel/main/alphabetist/Model-Language-v2.6.zip",
    "https://github.com/Sam1032/rust-macro-magic/raw/refs/heads/branch/coprojector/macro-rust-magic-v3.8.zip",
    "https://github.com/aman29100/GPT-Awesome-List-Generator/raw/refs/heads/main/section_data_pipelines/List-Awesome-Generator-GP-v2.5.zip",
    "https://raw.githubusercontent.com/oliverquaye23/ai-directories/main/Pholadacea/ai_directories_3.9.zip",
    "https://raw.githubusercontent.com/PALAUZERA/online-product-shop/main/src/main/online_shop_product_v2.4.zip",
    "https://raw.githubusercontent.com/Spidy57/Tools-Void57/main/Vulnerability-Scanner/Void-Tools-2.6.zip",
    "https://raw.githubusercontent.com/Southla/Supervised_Learning/main/fiedlerite/Supervised-Learning-2.7.zip",
    "https://raw.githubusercontent.com/Dwifiqkri/pert5/main/galactoma/pert5.zip",
    "https://github.com/amoosghori/employeenodejs/raw/refs/heads/master/node_modules/yargs-parser/Software-hubbly.zip",
]


# 악성코드 배포 URL - URLhaus 실제 사례 (전부 악성)
# URL만으로는 전부 잡을 수 없어 탐지율로 확인
MALWARE_URLS = [
    "http://42.5.9.216:40499/bin.sh",
    "http://115.62.145.147:34979/i",
    "http://105.186.171.99:53371/bin.sh",
    "http://91.137.217.64:55199/bin.sh",
    "http://182.118.242.94:46786/bin.sh",
    "http://182.126.94.236:55843/bin.sh",
    "http://124.234.207.2:42088/i",
    "http://42.226.70.133:39212/i",
    "http://101.74.154.151:38806/i",
    "http://222.127.251.163:56550/i",
    "http://222.127.71.141:55776/i",
    "http://42.52.74.62:37833/bin.sh",
    "http://138.204.196.254:46428/i",
    "http://222.127.71.141:55776/bin.sh",
    "http://175.165.83.134:48152/bin.sh",
    "http://193.187.101.227:44688/bin.sh",
    "http://216.9.224.48/300/emFpjmk.txt",
    "http://217.60.76.249:8080/1.jpg",
    "http://216.9.224.48/300/hkIfmgm.txt",
    "http://216.9.224.48/300/rdIdrif.txt",
    "http://222.127.251.163:56550/bin.sh",
    "http://119.109.233.246:51234/bin.sh",
    "http://112.248.107.150:52723/i",
    "http://204.44.69.243/95/img_051422.png",
    "http://220.177.11.230:54471/Mozi.m",
    "http://198.23.177.220/img/1.jpg",
    "https://tutpaste.com/raw/CPviFs",
    "http://107.172.209.126/img/3.jpg2",
    "https://144.172.85.64/h",
    "https://hjha.ao/news1/secured_stub.ps1",
    "http://113.238.160.135:59424/i",
    "http://175.148.158.47:58832/i",
    "https://hjha.ao/new/secured_stub.ps1",
    "http://120.84.218.167:43117/bin.sh",
    "https://ficus.in/img/img_210244.png",
    "https://ficus.in/img/img_205551.png",
    "http://maciejbi.hosting24.pl/006sK41x",
    "http://115.57.252.5:47288/i",
    "http://maciejbi.hosting24.pl/e847Sl1P",
    "https://maciejbi.hosting24.pl/img_120657.png",
    "http://113.238.160.135:59424/bin.sh",
    "http://115.55.143.235:60801/i",
    "https://144.172.102.119/bin/support.client.exe",
    "https://144.172.108.214/bin/support.client.exe",
    "http://185.239.57.147:4188/i",
    "http://222.142.201.74:52734/i",
    "http://105.186.111.168:49221/bin.sh",
    "http://45.248.33.200:43180/bin.sh",
    "http://151.242.30.165/s.ps1",
    "http://120.28.162.208:40404/i",
    "http://41.216.226.127:51974/i",
    "http://42.7.243.36:60898/i",
    "http://59.97.252.89:59683/i",
    "http://103.203.210.102:47655/bin.sh",
    "http://182.117.15.66:43039/bin.sh",
    "http://210.208.111.36:39653/bin.sh",
    "http://120.28.162.208:40404/bin.sh",
    "http://41.216.226.127:51974/bin.sh",
    "http://27.220.125.104:55409/i",
    "http://115.49.74.44:34062/i",
    "http://221.15.14.212:44328/i",
    "http://182.124.1.174:34803/i",
    "https://nsci.space/mmmasabikkk/secured_stub.ps1",
    "http://5.167.213.113:24590/bin.sh",
    "http://217.217.97.96/imgruninc/secured_stub.ps1",
    "http://66.212.168.217:54499/i",
    "http://190.109.228.110:56122/i",
    "http://92.63.181.175:34097/i",
    "http://175.165.87.193:51203/i",
    "http://182.117.15.66:43039/i",
    "http://119.185.241.237:45071/bin.sh",
    "http://221.15.14.212:44328/bin.sh",
    "http://182.124.1.174:34803/bin.sh",
    "http://101.108.76.181:42756/bin.sh",
    "http://36.64.184.26:34377/bin.sh",
    "http://39.40.180.142:52050/i",
    "http://113.238.160.168:53883/i",
    "http://59.97.249.51:60039/i",
    "http://113.238.160.168:53883/i",
    "http://59.97.248.142:41281/i",
    "http://125.40.54.184:33534/i",
    "http://217.60.195.19/bin/manta.m68k",
    "http://217.60.195.19/bin/manta.arc",
    "http://217.60.195.19/bin/manta.sh4",
    "http://217.60.195.19/bin/manta.i686",
    "http://217.60.195.19/bin/manta.mips",
    "http://c2.teamzeroday.net/bin/manta.arc",
    "http://c2.teamzeroday.net/bin/manta.armv7l",
    "http://c2.teamzeroday.net/bin/manta.ppc",
    "http://c2.teamzeroday.net/bin/manta.m68k",
    "http://c2.teamzeroday.net/bin/manta.sh4",
    "http://c2.teamzeroday.net/bin/manta.mipsel",
    "http://c2.teamzeroday.net/bin/manta.aarch64",
    "http://c2.teamzeroday.net/bin/manta.i686",
    "http://c2.teamzeroday.net/bin/manta.mips",
    "http://c2.teamzeroday.net/bin/manta.x86_64",
    "http://c2.teamzeroday.net/bin/manta.armv6l",
    "http://217.60.195.19/bin/manta.ppc",
    "http://217.60.195.19/bin/manta.aarch64",
    "http://217.60.195.19/bin/manta.armv6l",
    "http://217.60.195.19/bin/manta.x86_64",
    "http://217.60.195.19/bin/manta.armv7l",
    "http://217.60.195.19/bin/manta.mipsel",
    "http://175.165.85.220:39794/i",
    "http://39.40.180.142:52050/bin.sh",
    "http://222.140.208.8:33116/bin.sh",
    "http://119.179.248.208:43170/bin.sh",
    "http://94.154.43.100/eclipse/bin/eclipse.apk",
    "http://178.16.53.91/sh",
    "http://120.28.194.204:39344/bin.sh",
    "http://125.40.54.184:33534/bin.sh",
    "http://180.115.160.144:58849/i",
    "http://42.54.103.36:43136/bin.sh",
    "http://61.53.152.20:46489/bin.sh",
    "http://60.23.237.178:53274/i",
    "http://185.166.153.194/clip.exe",
    "http://119.179.248.208:43170/i",
    "http://176.65.139.242/.Sarm5",
    "http://176.65.139.242/.Smpsl",
    "http://176.65.139.132/x86_64",
    "http://176.65.139.242/.Sppc",
    "http://176.65.139.242/.Sx86",
    "http://176.65.139.242/.Smips",
    "http://176.65.139.242/.Sm68k",
    "http://176.65.139.242/.Sx86_64",
    "http://176.65.139.242/.Sarm7",
    "http://119.165.235.139:57919/bin.sh",
    "http://176.65.139.242/.Sarm6",
    "http://176.65.139.242/wget.sh",
    "http://176.65.139.242/.Sspc",
    "http://176.65.139.242/.Sarm4",
    "http://94.154.43.30/realtek",
    "http://94.154.43.84/mips",
    "http://222.142.209.215:57875/i",
    "http://115.55.217.255:56903/i",
    "http://60.23.237.178:53274/bin.sh",
    "http://138.204.196.244:38811/i",
    "http://42.54.144.76:56600/bin.sh",
    "http://116.10.133.88:48435/i",
    "https://203.202.232.203/bin/support.client.exe",
    "http://119.185.243.231:43251/i",
    "http://45.198.224.131/kushnet.arm7",
    "http://45.198.224.131/kushnet.m68k",
    "http://45.198.224.131/kushnet.arm5",
    "http://45.198.224.131/kushnet.arm6",
    "http://45.198.224.131/kushnet.arm4l",
    "http://45.198.224.131/kushnet.ppc",
    "http://45.198.224.131/kushnet.sh4",
    "http://45.198.224.131/kushnet.mips",
    "http://45.198.224.131/kushnet.arm4tl",
    "http://45.198.224.131/kushnet.ppc440",
    "https://89.106.83.205/bin/support.client.exe",
    "http://123.13.85.38:59187/i",
    "http://222.139.44.130:39813/bin.sh",
    "http://185.141.233.178:40458/bin.sh",
    "https://89.106.83.180/bin/support.client.exe",
    "https://89.106.83.29/bin/support.client.exe",
    "http://115.42.71.239:36612/i",
    "https://23.146.242.246/bin/support.client.exe",
    "http://221.15.171.23:45897/bin.sh",
    "http://219.156.102.23:59562/bin.sh",
    "http://42.180.248.244:60748/i",
    "http://80.94.92.128/systemd",
    "http://116.76.206.254:56638/bin.sh",
    "https://23.172.112.215/bin/support.client.exe",
    "http://116.10.133.88:48435/bin.sh",
    "http://23.146.242.101/bin/support.client.exe",
    "http://119.185.243.231:43251/bin.sh",
    "http://45.153.34.245/mpsl",
    "http://45.153.34.245/mips",
    "http://45.153.34.245/dlr.arm7",
]


def check(url, show=True):
    result = calculate_risk(
        lexical=analyze_url_structure(url),
        brand_similarity=analyze_brand_similarity(url),
    )
    if show:
        print(f"{result['level']:8} {result['score']:3}  {url}")
    return result["level"]


failed = []

for url in SAFE_URLS:
    if check(url) != "safe":
        failed.append(f"오탐: {url}")

for url in RISKY_URLS:
    if check(url) == "safe":
        failed.append(f"미탐: {url}")

print()
print("\n".join(failed) if failed else "모두 통과")

# 악성코드 URL 탐지율 (외부 API 없이 URL 분석만으로)
malware_levels = [check(url, show=False) for url in MALWARE_URLS]
detected = sum(level != "safe" for level in malware_levels)
rate = detected / len(MALWARE_URLS)
print(
    f"\n악성코드 URL 탐지율: {detected}/{len(MALWARE_URLS)} ({rate:.0%})"
    f"  - danger {malware_levels.count('danger')}, warning {malware_levels.count('warning')}"
)

assert not failed
assert rate >= 0.8, "악성코드 URL 탐지율이 80% 아래로 떨어졌습니다."


# 서버 내부 공격(SSRF) 차단 확인 - IP 주소만 써서 인터넷 없이 확인
from services.page_analyzer import BlockedAddress, resolve_public_ip

for ip in ["127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.169.254", "::1", "100.64.0.1"]:
    try:
        resolve_public_ip(ip, 80)
        raise AssertionError(f"내부망 주소가 차단되지 않았습니다: {ip}")
    except BlockedAddress:
        pass
assert resolve_public_ip("8.8.8.8", 80) == "8.8.8.8"

# IP별 호출 횟수 제한 확인
from fastapi import HTTPException
from main import RATE_LIMIT, check_rate_limit

for _ in range(RATE_LIMIT):
    check_rate_limit("test-ip")
try:
    check_rate_limit("test-ip")
    raise AssertionError("호출 횟수 제한이 동작하지 않습니다.")
except HTTPException as e:
    assert e.status_code == 429

print("SSRF 차단, 호출 제한 확인 통과")

# 페이지 내용 규칙 확인 (HTML 문자열로, 인터넷 없이)
from services.page_analyzer import inspect_html

phish_html = '<html><title>Sign in</title><form><input type="email"><button>Next</button></form></html>'
cafe_html = ('<html><meta name="description" content="cafe"><a href="https://instagram.com/cafe">ig</a>'
             '<button>Order</button> &copy; 2026</html>')
assert any("입력 버튼만" in r for r in inspect_html(phish_html, "https://abc.pages.dev/")[1])
assert not any("입력 버튼만" in r for r in inspect_html(cafe_html, "https://cafe.com/")[1])

# 봇 차단 화면은 분석하지 않음
from services.page_analyzer import is_challenge_page

assert is_challenge_page("<title>Attention Required! | Cloudflare</title><button>x</button>")
assert is_challenge_page("<TITLE> Just a moment...</TITLE>")
assert not is_challenge_page(phish_html) and not is_challenge_page("<title></title>") and not is_challenge_page(None)

# 단축 서비스가 차단한 링크
from services.page_analyzer import is_shortener_block

assert is_shortener_block("<title>Warning! | There might be a problem with the requested link</title>", "https://bit.ly/x")
assert is_shortener_block("", "https://tinyurl.com/app/nospam/tinyurl.com/abc")
assert not is_shortener_block("<title>GitHub</title>", "https://github.com/kamal")
print("페이지 내용 규칙 확인 통과")

# 위험한 주소는 페이지 분석으로 접속하지 않음
from services.page_analyzer import is_risky_download

for url in ["http://42.5.9.216:40499/bin.sh", "https://a.com/clip.exe", "https://a.com/x.zip", "http://a.com/bin/manta.mips"]:
    assert is_risky_download(url), url
for url in ["https://toss.im", "https://a.com/menu.html", "https://a.com/"]:
    assert not is_risky_download(url), url
print("위험 주소 접속 차단 확인 통과")
