from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
import ipaddress

# ==========================================
# THREAT SCAN SCHEMAS
# ==========================================

class ThreatScanRequest(BaseModel):
    """
    Schema for analyzing incoming requests.
    Validates that client data meets expected security parameters before processing.
    """
    source_ip: str = Field(
        ..., 
        description="The client IP address to evaluate for threat reputation.",
        examples=["192.168.1.50", "2001:db8::1"]
    )
    target_endpoint: str = Field(
        ..., 
        description="The endpoint the client is requesting.",
        examples=["/api/v1/auth/login"]
    )
    payload: str = Field(
        "", 
        description="The raw request body or query parameter payload to scan for injection/malicious signatures.",
        examples=["SELECT * FROM users WHERE id = 1;"]
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        """
        Cybersecurity check: Validates if the provided source IP is a syntactically valid IPv4 or IPv6 address.
        Prevents downstream security engines from breaking or misinterpreting malformed addresses.
        """
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")


class ThreatScanResponse(BaseModel):
    """
    Schema returned after threat scanning.
    Identifies whether the request should be blocked.
    """
    is_malicious: bool = Field(..., description="Flag indicating if the threshold was exceeded and request should be dropped.")
    threat_score: int = Field(..., ge=0, le=100, description="Calculated threat probability score (0 to 100).")
    threat_type: str = Field(..., description="Class of threat detected (e.g. BENIGN, SQL_INJECTION, PHISHING, etc.)")
    severity: str = Field(..., description="Risk tier: SAFE, LOW RISK, SUSPICIOUS, HIGH RISK, or DANGEROUS")
    matched_rules: List[str] = Field(default=[], description="List of signatures or heuristic rules triggered during analysis.")
    explanations: List[str] = Field(default=[], description="Detailed text justifications explaining why rules were triggered.")
    redirect_history: List[str] = Field(default=[], description="List of redirect hop URLs traversed during expansion.")
    expanded_url: Optional[str] = Field(None, description="The final destination URL after resolving redirect chains.")
    homograph_details: Optional[dict] = Field(None, description="Unicode homograph analysis report details.")
    heuristic_details: Optional[dict] = Field(None, description="Detailed score details from the heuristics engine.")


# ==========================================
# THREAT ALERT SCHEMAS
# ==========================================

class ThreatAlertCreate(BaseModel):
    """Schema for creating a threat alert entry."""
    source_ip: str
    target_endpoint: str
    threat_type: str
    severity: str
    threat_score: int
    payload_preview: Optional[str] = None
    redirect_chain: Optional[str] = None
    heuristic_matches: Optional[str] = None
    homograph_findings: Optional[str] = None
    tld_match: Optional[str] = None
    expanded_url: Optional[str] = None


class ThreatAlertResponse(BaseModel):
    """Schema for returning threat alert database entries to threat analysis dashboard."""
    id: int
    timestamp: datetime
    source_ip: str
    target_endpoint: str
    threat_type: str
    severity: str
    threat_score: int
    payload_preview: Optional[str]
    redirect_chain: Optional[str]
    heuristic_matches: Optional[str]
    homograph_findings: Optional[str]
    tld_match: Optional[str]
    expanded_url: Optional[str]
    resolved: bool
    resolution_notes: Optional[str]

    class Config:
        from_attributes = True  # Allows Pydantic to read SQLAlchemy models directly


# ==========================================
# IP BLACKLIST SCHEMAS
# ==========================================

class IPBlacklistCreate(BaseModel):
    """Schema for blacklisting a malicious IP address."""
    ip_address: str = Field(..., description="IPv4 or IPv6 address to blacklist.")
    reason: str = Field(..., min_length=5, description="Justification for blocking this IP address.")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration time. If empty, blacklist is permanent.")

    @field_validator("ip_address")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")


class IPBlacklistResponse(BaseModel):
    """Schema representing a blacklisted IP status."""
    id: int
    ip_address: str
    reason: str
    added_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True
