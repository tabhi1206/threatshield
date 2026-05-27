from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from database.models import ThreatAlert

# =============================
# Analytics Service Layer
# =============================

def get_analytics_summary(db: Session):
    """
    Returns dashboard summary: total scans, malicious/suspicious/safe counts, top rules, redirect stats, homograph counts, blacklist matches.
    """
    total_scans = db.query(func.count(ThreatAlert.id)).scalar() or 0

    malicious = db.query(func.count(ThreatAlert.id)).filter(
        ThreatAlert.severity.in_(['HIGH RISK', 'DANGEROUS', 'CRITICAL', 'MALICIOUS'])
    ).scalar() or 0
    suspicious = db.query(func.count(ThreatAlert.id)).filter(
        ThreatAlert.severity.in_(['SUSPICIOUS', 'MEDIUM', 'LOW RISK'])
    ).scalar() or 0
    safe = db.query(func.count(ThreatAlert.id)).filter(
        ThreatAlert.severity.in_(['SAFE', 'INFO', 'BENIGN'])
    ).scalar() or 0

    top_rule = db.query(ThreatAlert.heuristic_matches).filter(
        ThreatAlert.heuristic_matches.isnot(None),
        ThreatAlert.heuristic_matches != ""
    ).group_by(ThreatAlert.heuristic_matches).order_by(
        desc(func.count(ThreatAlert.heuristic_matches))
    ).first()

    recent_alerts = db.query(
        ThreatAlert.redirect_chain,
        ThreatAlert.homograph_findings,
        ThreatAlert.threat_type
    ).all()

    redirects = 0
    homographs = 0
    blacklist = 0

    for redirect_chain, homograph_findings, threat_type in recent_alerts:
        if redirect_chain:
            redirects += max(redirect_chain.count(",") + 1, 1)
        if homograph_findings:
            homographs += 1
        if threat_type and "BLACKLIST" in threat_type.upper():
            blacklist += 1

    return {
        "total_scans": total_scans,
        "malicious": malicious,
        "suspicious": suspicious,
        "safe": safe,
        "top_rule": top_rule[0] if top_rule else None,
        "redirects": redirects,
        "homographs": homographs,
        "blacklist": blacklist
    }

def get_analytics_trends(db: Session):
    """
    Returns threat trends over time for charting.
    """
    # Group by date, count threats
    rows = db.query(
        func.strftime('%Y-%m-%d', ThreatAlert.timestamp).label('date'),
        func.count(ThreatAlert.id)
    ).group_by('date').order_by('date').all()
    return {
        "dates": [r[0] for r in rows],
        "counts": [r[1] for r in rows]
    }

def get_analytics_recent(db: Session):
    """
    Returns recent incidents for the incidents table.
    """
    alerts = db.query(ThreatAlert).order_by(desc(ThreatAlert.timestamp)).limit(50).all()
    return [
        {
            "timestamp": str(a.timestamp),
            "source_ip": a.source_ip,
            "target": a.target_endpoint,
            "severity": a.severity,
            "rules": a.heuristic_matches,
            "expanded_url": a.expanded_url,
            "redirect_depth": (a.redirect_chain.count(",") + 1) if a.redirect_chain else 0
        }
        for a in alerts
    ]

def get_analytics_severity_distribution(db: Session):
    """
    Returns severity distribution for pie/doughnut chart.
    """
    rows = db.query(ThreatAlert.severity, func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()
    labels = [r[0] for r in rows]
    data = [r[1] for r in rows]
    return {"labels": labels, "data": data}
