from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.connection import get_db
from services.analytics import (
    get_analytics_summary,
    get_analytics_trends,
    get_analytics_recent,
    get_analytics_severity_distribution
)

router = APIRouter(prefix="/analytics", tags=["Analytics"])

@router.get("/summary")
def analytics_summary(db: Session = Depends(get_db)):
    """
    Returns dashboard summary: total scans, malicious/suspicious/safe counts, top rules, redirect stats, homograph counts, blacklist matches.
    """
    return get_analytics_summary(db)

@router.get("/trends")
def analytics_trends(db: Session = Depends(get_db)):
    """
    Returns threat trends over time for charting.
    """
    return get_analytics_trends(db)

@router.get("/recent")
def analytics_recent(db: Session = Depends(get_db)):
    """
    Returns recent incidents for the incidents table.
    """
    return get_analytics_recent(db)

@router.get("/severity-distribution")
def analytics_severity_distribution(db: Session = Depends(get_db)):
    """
    Returns severity distribution for pie/doughnut chart.
    """
    return get_analytics_severity_distribution(db)
