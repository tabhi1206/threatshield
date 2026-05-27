import time
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from database.connection import get_db

router = APIRouter(prefix="/health", tags=["System Health"])

@router.get("", response_model=dict)
def get_health(db: Session = Depends(get_db)):
    """
    Performs a system health check.
    Validates backend server availability and active connectivity to the SQLite database.
    This endpoint is used by orchestrators (like Kubernetes or Docker) to monitor service liveness.
    """
    start_time = time.time()
    db_status = "UP"
    db_latency_ms = 0.0

    try:
        # Measure database round-trip time (RTT) using a lightweight SQL query
        db_start = time.time()
        db.execute(text("SELECT 1"))
        db_latency_ms = round((time.time() - db_start) * 1000, 2)
    except Exception as e:
        db_status = f"DOWN: {str(e)}"

    total_latency_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "status": "HEALTHY" if "DOWN" not in db_status else "DEGRADED",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "services": {
            "api_server": "UP",
            "database": {
                "status": db_status,
                "latency_ms": db_latency_ms
            }
        },
        "response_time_ms": total_latency_ms
    }
