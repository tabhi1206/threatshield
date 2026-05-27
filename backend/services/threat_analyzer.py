import re
from typing import List, Tuple, Dict, Any
from sqlalchemy.orm import Session
from config.settings import settings
from database.models import ThreatAlert, IPBlacklist
from models.threat import ThreatScanRequest, ThreatScanResponse
from utils.security import calculate_entropy, is_bogon_or_private_ip, sanitize_log_data

# Import the new cybersecurity intelligence services
from services.homograph_detector import HomographDetector
from services.url_heuristics import URLHeuristicsAnalyzer
from services.redirect_analyzer import RedirectAnalyzer
from urllib.parse import urlparse

class ThreatAnalyzerService:
    """
    Unified Threat Intelligence and Scoring Engine.
    Orchestrates URL expansion, homograph checks, heuristics, and payload scanning
    to compile a weighted risk matrix.
    """

    # Payload Signature scans for SQLi, XSS, and Command Injections
    SQLI_SIGNATURES = [
        re.compile(r"union\s+select", re.IGNORECASE),
        re.compile(r"select\s+.*\s+from", re.IGNORECASE),
        re.compile(r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.IGNORECASE),
        re.compile(r"--;", re.IGNORECASE),
        re.compile(r"/\*.*\*/", re.IGNORECASE),
        re.compile(r"drop\s+table", re.IGNORECASE),
        re.compile(r"information_schema", re.IGNORECASE)
    ]

    XSS_SIGNATURES = [
        re.compile(r"<script.*?>", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE),
        re.compile(r"src\s*=\s*['\"]data:", re.IGNORECASE),
        re.compile(r"eval\(.*?\)", re.IGNORECASE),
        re.compile(r"document\.cookie", re.IGNORECASE)
    ]

    CMDI_SIGNATURES = [
        re.compile(r"\.\./\.\.", re.IGNORECASE),
        re.compile(r"/etc/passwd", re.IGNORECASE),
        re.compile(r"\b(cat|tac|head|tail|more|less)\s+\/\w+", re.IGNORECASE),
        re.compile(r"\b(cmd\.exe|powershell\.exe|sh|bash)\b", re.IGNORECASE),
        re.compile(r"[;&|]\s*\b(ping|curl|wget|nc|netcat)\b", re.IGNORECASE)
    ]

    @classmethod
    def scan_request(cls, request: ThreatScanRequest, db: Session) -> ThreatScanResponse:
        """
        Main pipeline executing end-to-end threat inspection on client payloads.
        """
        source_ip = request.source_ip
        raw_payload = request.payload
        target_endpoint = request.target_endpoint

        matched_rules: List[str] = []
        explanations: List[str] = []
        redirect_history: List[str] = []
        expanded_url = raw_payload
        
        # Threat score metrics
        ip_score = 0
        redirect_score = 0
        homograph_score = 0
        heuristic_score = 0
        signature_score = 0
        
        homograph_details = None
        heuristic_details = None

        # ----------------------------------------------------
        # STEP 1: IP Blacklist & IP Metadata Reputation
        # ----------------------------------------------------
        is_blacklisted = db.query(IPBlacklist).filter(
            IPBlacklist.ip_address == source_ip,
            IPBlacklist.is_active == True
        ).first()

        if is_blacklisted:
            matched_rules.append("IP_ON_BLACKLIST")
            explanations.append(f"Source IP is flagged on central blocklist: {is_blacklisted.reason}")
            ip_score = 100  # Instant critical override
        elif is_bogon_or_private_ip(source_ip):
            matched_rules.append("PRIVATE_OR_BOGON_IP")
            explanations.append("Source IP is unallocated or belongs to RFC 1918 private subnets.")
            ip_score = 15

        # ----------------------------------------------------
        # STEP 2: Redirect Analysis and URL Expansion
        # If the input payload resembles a web URL, expand redirects.
        # ----------------------------------------------------
        is_url = False
        if raw_payload and (raw_payload.startswith("http://") or raw_payload.startswith("https://") or "." in urlparse(raw_payload).path or "/" in raw_payload):
            is_url = True

        if is_url and ip_score < 100:
            # Add protocol prefix if parsing requires it
            test_url = raw_payload
            if not test_url.startswith("http://") and not test_url.startswith("https://"):
                test_url = "http://" + test_url
                
            redirect_report = RedirectAnalyzer.resolve_redirects(test_url)
            expanded_url = redirect_report["expanded_url"]
            redirect_history = redirect_report["redirect_history"]
            redirect_score = redirect_report["score"]
            
            if redirect_report["is_shortened"]:
                matched_rules.append("URL_SHORTENER_OBFUSCATION")
            if redirect_report["redirect_depth"] >= 3:
                matched_rules.append("EXCESSIVE_REDIRECT_DEPTH")
            
            explanations.extend(redirect_report["explanations"])

        # Determine target hostname for downstream scans
        parsed_target = urlparse(expanded_url)
        target_hostname = parsed_target.hostname or target_endpoint or ""
        target_tld = target_hostname.split(".")[-1] if "." in target_hostname else ""

        # ----------------------------------------------------
        # STEP 3: Unicode Homograph Spoofing Analysis
        # ----------------------------------------------------
        if target_hostname and ip_score < 100:
            homograph_report = HomographDetector.analyze_domain(target_hostname)
            homograph_score = homograph_report["score_contribution"]
            homograph_details = homograph_report
            
            if homograph_report["is_homograph"]:
                matched_rules.append("HOMOGRAPH_ATTACK_DETECTION")
                explanations.append(homograph_report["explanation"])
            elif homograph_report["is_idn"]:
                matched_rules.append("INTERNATIONALIZED_DOMAIN_NAME")
                explanations.append(homograph_report["explanation"])

        # ----------------------------------------------------
        # STEP 4: Advanced URL Heuristics Analysis
        # ----------------------------------------------------
        if is_url and ip_score < 100:
            heuristics_report = URLHeuristicsAnalyzer.analyze_url(expanded_url)
            heuristic_score = heuristics_report["score"]
            heuristic_details = heuristics_report
            
            if heuristics_report["rules"]:
                matched_rules.extend(heuristics_report["rules"])
                explanations.extend(heuristics_report["explanations"])

        # ----------------------------------------------------
        # STEP 5: Traditional WAF Signature Scanning
        # Run matches against query strings and payload values.
        # ----------------------------------------------------
        if raw_payload and ip_score < 100:
            # Check SQL Injection (SQLi)
            sqli_matches = sum(1 for pattern in cls.SQLI_SIGNATURES if pattern.search(raw_payload))
            if sqli_matches > 0:
                matched_rules.append(f"SQLI_SIGNATURE_MATCH ({sqli_matches})")
                signature_score += 35 * sqli_matches
                explanations.append("SQL query signatures detected inside payload.")

            # Check Cross-Site Scripting (XSS)
            xss_matches = sum(1 for pattern in cls.XSS_SIGNATURES if pattern.search(raw_payload))
            if xss_matches > 0:
                matched_rules.append(f"XSS_SIGNATURE_MATCH ({xss_matches})")
                signature_score += 40 * xss_matches
                explanations.append("Inline script code patterns detected inside payload.")

            # Check Command Injection (CMDi)
            cmdi_matches = sum(1 for pattern in cls.CMDI_SIGNATURES if pattern.search(raw_payload))
            if cmdi_matches > 0:
                matched_rules.append(f"COMMAND_INJECTION_MATCH ({cmdi_matches})")
                signature_score += 45 * cmdi_matches
                explanations.append("Terminal commands/path manipulation patterns detected inside payload.")

            # Evaluate payload entropy
            entropy = calculate_entropy(raw_payload)
            if len(raw_payload) > 15 and entropy > 5.2:
                matched_rules.append(f"HIGH_PAYLOAD_ENTROPY ({entropy})")
                signature_score += 25
                explanations.append("Abnormally high character entropy, indicating encrypted/obfuscated code block.")

        # ----------------------------------------------------
        # STEP 6: Central Score Calculation & Severity Mapping
        # ----------------------------------------------------
        if ip_score == 100:
            threat_score = 100
        else:
            # Weighted addition capped at 100
            threat_score = min(ip_score + redirect_score + homograph_score + heuristic_score + signature_score, 100)

        # Map threat score to revised Phase 3 severity classifications
        if threat_score >= 85:
            severity = "DANGEROUS"
            threat_type = "PHISHING_MALICIOUS_SITE" if is_url else "CRITICAL_PAYLOAD_EXPLOIT"
        elif threat_score >= 60:
            severity = "HIGH RISK"
            threat_type = "SUSPICIOUS_DOMAIN"
        elif threat_score >= 35:
            severity = "SUSPICIOUS"
            threat_type = "SUSPICIOUS_HEURISTIC"
        elif threat_score >= 11:
            severity = "LOW RISK"
            threat_type = "MINOR_FLAGS"
        else:
            severity = "SAFE"
            threat_type = "BENIGN"

        is_malicious = threat_score >= settings.MALICIOUS_THRESHOLD

        # ----------------------------------------------------
        # STEP 7: Persistent Logging (SQLite Update)
        # ----------------------------------------------------
        if threat_score > 0:
            try:
                alert = ThreatAlert(
                    source_ip=source_ip,
                    target_endpoint=target_hostname or target_endpoint,
                    threat_type=threat_type,
                    severity=severity,
                    threat_score=threat_score,
                    payload_preview=sanitize_log_data(raw_payload) if raw_payload else None,
                    redirect_chain=", ".join(redirect_history) if redirect_history else None,
                    heuristic_matches=", ".join(heuristic_details["rules"]) if heuristic_details and heuristic_details["rules"] else None,
                    homograph_findings=homograph_details["explanation"] if homograph_details else None,
                    tld_match=target_tld,
                    expanded_url=expanded_url,
                    resolved=False
                )
                db.add(alert)
                db.commit()
                db.refresh(alert)
            except Exception as db_err:
                db.rollback()
                print(f"Error logging threat alert to database: {str(db_err)}")

        return ThreatScanResponse(
            is_malicious=is_malicious,
            threat_score=threat_score,
            threat_type=threat_type,
            severity=severity,
            matched_rules=matched_rules,
            explanations=explanations,
            redirect_history=redirect_history,
            expanded_url=expanded_url,
            homograph_details=homograph_details,
            heuristic_details=heuristic_details
        )

