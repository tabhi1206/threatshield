from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.settings import settings
from database.connection import Base, engine
from routes.health import router as health_router
from routes.threats import router as threats_router
from routes.analytics import router as analytics_router

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
# This automatically creates SQLite tables on startup if they do not exist.
# For production pipelines, Alembic is recommended for database migrations,
# but automatic creation ensures a zero-setup startup for local testing.
Base.metadata.create_all(bind=engine)


# ==========================================
# FASTAPI APPLICATION SETUP
# ==========================================
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="ThreatShield API - High-performance cybersecurity threat detection and blacklisting backend.",
    docs_url="/docs",       # Swagger UI path
    redoc_url="/redoc"      # ReDoc path
)


# ==========================================
# CORS MIDDLEWARE
# ==========================================
# Configures Allowed Origins to prevent Cross-Origin Resource Sharing vulnerabilities (CWE-346).
# Restricting origins prevents malicious websites from invoking these API endpoints via browsers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],  # Restrict to specific HTTP methods in higher-security environments
    allow_headers=["*"],
)


# ==========================================
# CYBERSECURITY HEADERS MIDDLEWARE
# ==========================================
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Middleware injecting essential HTTP security headers into every API response.
    Protects against common client-side web vulnerabilities:
    - X-Frame-Options: Prevents Clickjacking attacks (CWE-1021).
    - X-Content-Type-Options: Prevents MIME-sniffing exploits (CWE-436).
    - Content-Security-Policy (CSP): Restricts source loads to mitigate XSS (CWE-79).
    - Strict-Transport-Security (HSTS): Forces HTTPS connection (CWE-523).
    - Referrer-Policy: Prevents sensitive path leakage in Referrer headers.
    """
    response = await call_next(request)
    
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    return response


# ==========================================
# GLOBAL EXCEPTION HANDLERS
# ==========================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception interceptor.
    Prevents verbose stack traces (which may leak sensitive path details or dependency
    versions to malicious actors) from being returned to the client.
    """
    # In production, log the full traceback securely inside internal log files
    print(f"CRITICAL ERROR: {str(exc)}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred. The incident has been logged and escalated."
        }
    )


# ==========================================
# ROUTER REGISTERING
# ==========================================
# Registers health check and cybersecurity operations routing under the configured API prefix (e.g. /api/v1)
app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(threats_router, prefix=settings.API_V1_STR)
app.include_router(analytics_router, prefix=settings.API_V1_STR)


# Root welcome path
@app.get("/", tags=["General"])
def read_root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} (v{settings.VERSION})",
        "status": "OPERATIONAL",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    # Local debugging entrypoint
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
