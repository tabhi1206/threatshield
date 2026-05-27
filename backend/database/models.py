import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from .connection import Base

class ThreatAlert(Base):
    """
    SQLAlchemy database model for logging detected security threats.
    Storing threat logs is vital for forensic investigations, compliance auditing,
    and training machine learning anomaly detection models.
    """
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # The source IP address that initiated the suspicious request
    source_ip = Column(String(45), nullable=False, index=True)  # Supports both IPv4 and IPv6 lengths (up to 45 chars)
    
    # The API endpoint/resource the client attempted to access
    target_endpoint = Column(String(255), nullable=False)
    
    # Class of threat (e.g., SQL_INJECTION, CROSS_SITE_SCRIPTING, MALICIOUS_IP, PAYLOAD_ENTROPY_HIGH)
    threat_type = Column(String(100), nullable=False)
    
    # Severity classification: LOW, MEDIUM, HIGH, CRITICAL
    severity = Column(String(20), nullable=False)
    
    # Threat score calculated by the analysis engine (0 = benign, 100 = critical threat)
    threat_score = Column(Integer, nullable=False)
    
    # Truncated or sanitized preview of the payload that triggered the alert
    payload_preview = Column(Text, nullable=True)
    
    # Advanced URL Threat Intelligence Columns
    redirect_chain = Column(Text, nullable=True)     # Stores comma-separated redirect URL list
    heuristic_matches = Column(Text, nullable=True)  # Stores comma-separated triggered rules
    homograph_findings = Column(Text, nullable=True) # Stores unicode homograph analysis details
    tld_match = Column(String(50), nullable=True)    # Extracted top-level domain
    expanded_url = Column(Text, nullable=True)       # Fully expanded short URL destination
    
    # Status field indicating if security operations center (SOC) has resolved the threat
    resolved = Column(Boolean, default=False)
    resolution_notes = Column(Text, nullable=True)


class IPBlacklist(Base):
    """
    SQLAlchemy database model for storing blacklisted IP addresses.
    IP blacklisting acts as a firewall rule at the application layer,
    instantly blocking requests from known malicious actors to protect application resources.
    """
    __tablename__ = "ip_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    
    # IP address to be blocked (IPv4 or IPv6)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    
    # Reason for the block (e.g., brute-force attack, repeated SQLi attempts)
    reason = Column(String(255), nullable=False)
    
    # Timestamp when the blacklisting rule was created
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Optional expiration time for temporary bans (null means permanent block)
    expires_at = Column(DateTime, nullable=True)
    
    # Active status toggle
    is_active = Column(Boolean, default=True, index=True)
