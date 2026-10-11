
# SafeQR Backend

SafeQR은 QR코드 및 URL을 통해 발생하는 피싱(큐싱, 스미싱) 피해를 예방하기 위한 악성 URL 탐지 프로젝트입니다.

본 레포지토리는 SafeQR의 백엔드 서버를 관리합니다.

## 1. 개발 환경

- Language: Python
- Framework: FastAPI
- Deployment: Render
- API Documentation: Swagger UI

## 2. 서버 주소

### Render 배포 서버
https://safeqr.onrender.com

### Swagger API 문서
https://safeqr.onrender.com/docs

## 3. 주요 기능

- URL 구조 및 문자열 특징 분석
- 정상 브랜드 도메인과의 유사도 분석
- 분석 결과에 따른 위험도 점수 계산
- URL 위험도 분류 (safe, warning, danger)
- JSON 형식의 분석 결과 제공

## 4. API 연동 방법

### URL 분석 API

- Method: POST
- Endpoint: /analyze
- Request URL: https://safeqr.onrender.com/analyze
- Content-Type: application/json

### Request Body

```json
{
  "url": "https://www.google.com"
}
```

### Response 예시

```json
{
  "url": "https://www.google.com",
  "domain": "www.google.com",
  "score": 0,
  "level": "safe",
  "analysis": {
    "lexical": {
      "score": 0,
      "reasons": []
    },
    "brand_similarity": {
      "score": 0,
      "reasons": []
    },
    "external_db": null,
    "domain_trust": null
  },
  "reasons": []
}
```

## 5. 위험도 분류

- safe: 안전
- warning: 주의
- danger: 위험

## 6. 향후 개발 계획

- 외부 악성 URL 데이터베이스 연동
- 도메인 신뢰도 분석 기능 추가
- Android 애플리케이션과 API 연동
- URL 탐지 정확도 개선
