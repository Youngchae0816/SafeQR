
from typing import List, Optional
from pydantic import BaseModel, Field


# URL 분석 요청 형식
class URLRequest(BaseModel):
    url: str


# 개별 분석 항목의 결과 형식
class AnalysisDetail(BaseModel):
    score: int = 0
    reasons: List[str] = Field(default_factory=list)


# 외부 위협 DB 분석 결과 형식
class ExternalDBResult(BaseModel):
    score: int = 0
    safe_browsing: Optional[bool] = None
    virustotal: Optional[bool] = None
    reasons: List[str] = Field(default_factory=list)

    # Google Safe Browsing API 응답
    status: Optional[str] = None
    message: Optional[str] = None
    matches: List[dict] = Field(default_factory=list)


# 도메인 신뢰도 분석 결과 형식
class DomainTrustResult(BaseModel):
    score: int = 0
    domain_age_days: Optional[int] = None
    reasons: List[str] = Field(default_factory=list)


# 전체 분석 세부 결과
class AnalysisResult(BaseModel):
    lexical: AnalysisDetail
    brand_similarity: AnalysisDetail
    external_db: Optional[ExternalDBResult] = None
    domain_trust: Optional[DomainTrustResult] = None


# 앱으로 최종 반환할 결과 형식
class URLAnalysisResponse(BaseModel):
    url: str
    domain: str
    score: int
    level: str
    analysis: AnalysisResult
    reasons: List[str] = Field(default_factory=list)
