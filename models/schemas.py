from typing import List, Optional

from pydantic import BaseModel


# URL 분석 요청 형식
class URLRequest(BaseModel):
    url: str


# 개별 분석 항목의 결과 형식
class AnalysisDetail(BaseModel):
    score: int = 0
    reasons: List[str] = []


# 외부 위협 DB 분석 결과 형식
class ExternalDBResult(BaseModel):
    score: int = 0
    safe_browsing: Optional[bool] = None
    reasons: List[str] = []


# 도메인 신뢰도 분석 결과 형식
class DomainTrustResult(BaseModel):
    score: int = 0
    domain_age_days: Optional[int] = None
    reasons: List[str] = []


# HTTPS 인증서 정보
class CertificateInfo(BaseModel):
    issuer: Optional[str] = None        # 발급기관 (예: Let's Encrypt)
    issued_at: Optional[str] = None     # 발급일 (YYYY-MM-DD)
    expires_at: Optional[str] = None    # 만료일
    age_days: Optional[int] = None      # 발급 후 지난 날짜


# 앱에 보여줄 사이트 정보
# title/description/site_name은 사이트가 스스로 밝힌 내용이라 그대로 믿으면 안 됨
class PageMetadata(BaseModel):
    final_url: str                      # 실제 도착한 주소
    redirect_chain: List[str] = []      # 거쳐 간 주소들 (처음 주소 포함)
    content_type: Optional[str] = None  # text/html, application/zip 등
    title: Optional[str] = None
    description: Optional[str] = None
    site_name: Optional[str] = None
    has_password_input: bool = False    # 비밀번호 입력창 여부
    https: bool = False                 # 암호화 연결 여부 (안전하다는 뜻은 아님)
    certificate: Optional[CertificateInfo] = None
    certificate_error: Optional[str] = None
    link_count: Optional[int] = None        # 페이지 안 링크 개수
    has_robots_txt: Optional[bool] = None   # 링크가 적을 때만 확인, 확인 안 했으면 null


# 페이지 내용(HTML) 분석 결과 형식
class PageResult(BaseModel):
    score: int = 0
    final_url: Optional[str] = None
    reasons: List[str] = []
    metadata: Optional[PageMetadata] = None


# 전체 분석 세부 결과
class AnalysisResult(BaseModel):
    lexical: AnalysisDetail
    brand_similarity: AnalysisDetail
    external_db: ExternalDBResult | None = None
    domain_trust: DomainTrustResult | None = None
    page: PageResult | None = None


# 앱으로 최종 반환할 결과 형식
class URLAnalysisResponse(BaseModel):
    url: str
    domain: str
    score: int
    level: str
    analysis: AnalysisResult
    reasons: List[str]