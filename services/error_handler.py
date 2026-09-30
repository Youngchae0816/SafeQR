from fastapi import Request
from fastapi.responses import JSONResponse


# 서버 내부에서 예상하지 못한 오류가 발생했을 때 처리
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "URL 분석 중 서버 오류가 발생했습니다."
        }
    )