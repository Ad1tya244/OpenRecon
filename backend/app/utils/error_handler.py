import logging
import sys
from typing import Dict, Any
from fastapi import Request, status
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

# Configure secure local logging
# We output to stdout for container/systemd capture.
# Log lines are structured.
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - OpenRecon - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger("OpenRecon")

# Error Mapping
# Maps Exception Class Name -> Response Config
ERROR_MAPPING = {
    "RateLimitExceeded": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Too many requests. Please try again later.",
        "status": status.HTTP_429_TOO_MANY_REQUESTS
    },
    "SafeHTTPError": {
        "code": "SAFE_HTTP_ERROR",
        "message": "Secure HTTP request failed (SSRF Protection or Network Error).",
        "status": status.HTTP_502_BAD_GATEWAY
    },
    "TimeoutError": {
        "code": "TIMEOUT",
        "message": "The operation timed out.",
        "status": status.HTTP_504_GATEWAY_TIMEOUT
    },
    "ValueError": {
        "code": "INVALID_INPUT",
        "message": "Invalid input provided.",
        "status": status.HTTP_400_BAD_REQUEST
    },
    "HTTPException": {
         # Handled broadly, but we can map specifics if needed
         "code": "BAD_REQUEST",
         "message": "Request validation failed.",
         "status": status.HTTP_400_BAD_REQUEST
    }
}

def log_error(exc: Exception, context: Dict[str, Any] = None):
    """
    Securely logs the error locally.
    Stack traces are logged locally but NEVER returned to user.
    """
    logger.error(f"Exception: {type(exc).__name__}: {str(exc)} | Context: {context}", exc_info=True)

async def centralized_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Global exception handler.
    Maps internal errors to safe, structured user responses.
    """
    exc_name = type(exc).__name__
    
    # 1. Log the error securely
    log_error(exc, {"path": request.url.path, "client": request.client.host})
    
    # 2. Map to safe response
    if exc_name in ERROR_MAPPING:
        mapping = ERROR_MAPPING[exc_name]
        return JSONResponse(
            status_code=mapping["status"],
            content={
                "error": {
                    "code": mapping["code"],
                    "message": mapping["message"]
                }
            }
        )
    
    # Special handling for explicit RateLimitExceeded (sometimes type name varies or we catch base)
    if isinstance(exc, RateLimitExceeded):
         return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "error": {
                    "code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests. Please try again later."
                }
            }
        )
        
    # Handle FastAPI HTTPExceptions nicely
    if exc_name == "HTTPException":
        # If it's the fastapi exception, it has 'detail' and 'status_code'
        return JSONResponse(
            status_code=getattr(exc, "status_code", 400),
            content={
                "error": {
                    "code": "REQUEST_ERROR",
                    "message": getattr(exc, "detail", "Invalid Request")
                }
            }
        )

    # Default / Fallback (Safe 500)
    # No stack trace here.
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred. The administrative team has been notified."
            }
        }
    )
