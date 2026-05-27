from .health import router as health_router
from .threats import router as threats_router
from .analytics import router as analytics_router

__all__ = ["health_router", "threats_router", "analytics_router"]
