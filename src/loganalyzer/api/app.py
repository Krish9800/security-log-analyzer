"""FastAPI application factory with OWASP defensive headers middleware."""

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from loganalyzer.api.routes import router
from loganalyzer.config.settings import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing OWASP defensive headers across all HTTP responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def get_app() -> FastAPI:
    """Create and configure FastAPI application instance."""
    application = FastAPI(
        title="Security Log Analyzer REST API",
        description="Multi-Format Forensic Ingestion, Sliding-Window Threat Correlator & MITRE ATT&CK Tagger API",
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Security headers
    application.add_middleware(SecurityHeadersMiddleware)

    # CORS configuration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    application.include_router(router)
    return application


app = get_app()
