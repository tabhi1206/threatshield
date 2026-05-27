from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import ThreatAlert, IPBlacklist
from models.threat import (
    ThreatScanRequest,
    ThreatScanResponse,
    ThreatAlertResponse,
    IPBlacklistCreate,
    IPBlacklistResponse
)
from services.threat_analyzer import ThreatAnalyzerService
from utils.security import sanitize_log_data

router = APIRouter(prefix="/threats", tags=["Threat Management & Scanning"])

# ==========================================
# THREAT SCANNING ENDPOINT
# ==========================================

@router.post(
    "/scan", 
    response_model=ThreatScanResponse, 
    status_code=status.HTTP_200_OK,
    summary="Scan payload and IP for cyber threat indicators"
)
def scan_payload(
    request: ThreatScanRequest, 
    db: Session = Depends(get_db)
):
    """
    Entrypoint for scanning incoming HTTP requests.
    Validates the source IP against blacklists, matches patterns against signatures
    (SQLi, XSS, Path Traversal), and computes a threat score.
    
    If the computed threat score is >= the configured threshold (e.g., 50),
    the endpoint flags it as malicious. The caller application should reject the client's request.
    """
    return ThreatAnalyzerService.scan_request(request, db)


# ==========================================
# THREAT ALERTS ENDPOINTS
# ==========================================

@router.get(
    "/alerts", 
    response_model=List[ThreatAlertResponse],
    summary="List all captured threat alerts"
)
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    limit: int = Query(50, ge=1, le=100, description="Max alerts to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db)
):
    """
    Retrieves threat alerts logged by the scanner.
    Used by Security Operations Center (SOC) dashboards to audit incidents.
    """
    query = db.query(ThreatAlert)
    
    if severity:
        query = query.filter(ThreatAlert.severity == severity.upper())
    if resolved is not None:
        query = query.filter(ThreatAlert.resolved == resolved)
        
    alerts = query.order_by(ThreatAlert.timestamp.desc()).limit(limit).offset(offset).all()
    return alerts


@router.put(
    "/alerts/{alert_id}/resolve", 
    response_model=ThreatAlertResponse,
    summary="Mark an alert as resolved/mitigated"
)
def resolve_alert(
    alert_id: int, 
    notes: str = Query(..., min_length=5, description="Notes on resolution steps taken"),
    db: Session = Depends(get_db)
):
    """
    Marks an alert as resolved.
    Security analysts record their triage steps in the notes field for future compliance audits.
    """
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Threat alert with ID {alert_id} not found."
        )
    
    alert.resolved = True
    alert.resolution_notes = sanitize_log_data(notes)
    
    db.commit()
    db.refresh(alert)
    return alert


# ==========================================
# IP BLACKLIST MANAGEMENT ENDPOINTS
# ==========================================

@router.post(
    "/blacklist", 
    response_model=IPBlacklistResponse, 
    status_code=status.HTTP_201_CREATED,
    summary="Add an IP address to the blacklist"
)
def add_to_blacklist(
    payload: IPBlacklistCreate, 
    db: Session = Depends(get_db)
):
    """
    Manually blacklists an IP address.
    Requests from blacklisted IPs are blocked instantly (threat score 100).
    """
    # Check if the IP is already blacklisted
    existing = db.query(IPBlacklist).filter(IPBlacklist.ip_address == payload.ip_address).first()
    
    if existing:
        if existing.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail=f"IP address {payload.ip_address} is already active on the blacklist."
            )
        else:
            # Re-activate the existing blacklist rule
            existing.is_active = True
            existing.reason = sanitize_log_data(payload.reason)
            existing.expires_at = payload.expires_at
            db.commit()
            db.refresh(existing)
            return existing

    new_rule = IPBlacklist(
        ip_address=payload.ip_address,
        reason=sanitize_log_data(payload.reason),
        expires_at=payload.expires_at,
        is_active=True
    )
    
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return new_rule


@router.get(
    "/blacklist", 
    response_model=List[IPBlacklistResponse],
    summary="List all blacklisted IP addresses"
)
def get_blacklist(
    active_only: bool = Query(True, description="Filter active blacklisted IPs only"),
    db: Session = Depends(get_db)
):
    """
    Returns lists of blocked IP ranges.
    Can be ingested by external network components or edge gateways.
    """
    query = db.query(IPBlacklist)
    if active_only:
        query = query.filter(IPBlacklist.is_active == True)
        
    return query.order_by(IPBlacklist.added_at.desc()).all()


@router.delete(
    "/blacklist/{ip_address}", 
    status_code=status.HTTP_200_OK,
    summary="Remove or deactivate an IP from the blacklist"
)
def remove_from_blacklist(
    ip_address: str, 
    db: Session = Depends(get_db)
):
    """
    Deactivates an active IP blacklist rule.
    Performs a soft delete (marking is_active=False) to maintain historical audit trails.
    """
    rule = db.query(IPBlacklist).filter(
        IPBlacklist.ip_address == ip_address.strip(), 
        IPBlacklist.is_active == True
    ).first()
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"Active blacklist rule for IP {ip_address} not found."
        )
        
    rule.is_active = False  # Soft delete to preserve log audit integrity
    db.commit()
    
    return {"status": "SUCCESS", "message": f"IP {ip_address} removed from active blacklist rules."}
