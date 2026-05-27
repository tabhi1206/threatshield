import re
from typing import Dict, Any, List
import ipaddress

class URLHeuristicsAnalyzer:
    """
    Heuristics Analysis Engine for URL-based threat intelligence.
    
    CYBERSECURITY PRINCIPLE: URL HEURISTICS
    Phishing URLs exhibit distinct structural patterns designed to evade static signature WAFs 
    while convincing victims of their legitimacy. By scoring structural anomalies—like 
    domain nesting, brand keyword injection, raw IP routing, and cheap/suspicious TLDs—we 
    can build a heuristic classification profile for zero-day phishing sites.
    """

    # Suspicious Top-Level Domains (TLDs) frequently abused in phishing campaigns (high malicious reputation)
    SUSPICIOUS_TLDS = {
        "xyz": 25,
        "top": 25,
        "tk": 30,
        "gq": 30,
        "cf": 30,
        "ml": 30,
        "cc": 20,
        "ru": 20,
        "cn": 20,
        "work": 15,
        "click": 15,
        "buzz": 15,
        "fit": 15,
        "country": 20,
        "stream": 20
    }

    # Keywords commonly injected into phishing URLs to simulate security or brand endpoints
    PHISHING_KEYWORDS = [
        "login", "signin", "verify", "verification", "secure", "security", "account",
        "update", "billing", "support", "confirm", "checkout", "paypal", "netflix",
        "microsoft", "apple", "google", "amazon", "chase", "wells Fargo", "bank",
        "credential", "recover", "authenticate", "portal"
    ]

    # Open Redirect parameters commonly abused to bounce users off legitimate sites onto malicious landings
    REDIRECT_PARAMS = ["redirect", "url", "next", "dest", "destination", "goto", "return", "r_link"]

    @classmethod
    def analyze_url(cls, url_string: str) -> Dict[str, Any]:
        """
        Runs a suite of structural checks against a URL to assess its threat profile.
        
        @param url_string: The raw URL to analyze.
        @returns: Heuristics summary, total heuristic score, and lists of triggered rules.
        """
        triggered_rules: List[str] = []
        explanations: List[str] = []
        heuristic_score = 0

        if not url_string:
            return {
                "score": 0,
                "rules": [],
                "explanations": ["Empty URL provided."]
            }

        # Safe parsing of URL parts
        hostname = ""
        path = ""
        query = ""
        
        try:
            # Add protocol prefix if missing, allowing standard URL parsing
            normalized_url = url_string
            if not re.match(r'^[a-zA-Z]+://', url_string):
                normalized_url = "http://" + url_string
                
            from urllib.parse import urlparse
            parsed = urlparse(normalized_url)
            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
        except Exception:
            # If URL parsing crashes, it indicates an exploit payload in the URI structure
            return {
                "score": 80,
                "rules": ["URL_PARSING_FAILURE"],
                "explanations": ["URL structure failed basic RFC parsing, indicating structural obfuscation."]
            }

        hostname = hostname.lower()
        path = path.lower()
        query = query.lower()

        # ----------------------------------------------------
        # 1. IP-Based Hostname Check
        # Standard websites use domain names. Using raw IP addresses bypasses DNS lookup records,
        # which is common in low-cost, automated phishing servers or local C2 setups.
        # ----------------------------------------------------
        is_ip = False
        try:
            # Try to parse as IPv4 or IPv6
            clean_host = hostname.split(':')[0] if ':' in hostname else hostname
            ipaddress.ip_address(clean_host)
            is_ip = True
            triggered_rules.append("IP_HOST")
            heuristic_score += 45
            explanations.append("Domain hostname is a raw IP address (bypasses DNS security inspection).")
        except ValueError:
            pass

        # ----------------------------------------------------
        # 2. Suspicious TLD Analysis
        # Attackers register domains under cheap, unmonitored TLDs (.xyz, .tk, etc.)
        # to deploy high-volume campaigns that can be easily discarded when blocked.
        # ----------------------------------------------------
        if not is_ip and "." in hostname:
            tld = hostname.split(".")[-1]
            if tld in cls.SUSPICIOUS_TLDS:
                weight = cls.SUSPICIOUS_TLDS[tld]
                triggered_rules.append(f"SUSPICIOUS_TLD_{tld.upper()}")
                heuristic_score += weight
                explanations.append(f"Domain is registered under high-risk TLD (.{tld}) commonly associated with phishing.")

        # ----------------------------------------------------
        # 3. Domain Nesting (Excessive Subdomains)
        # Deeply nested subdomains are used to spoof brands (e.g. www.paypal.com.security.site.xyz).
        # We check the subdomain depth count.
        # ----------------------------------------------------
        if not is_ip:
            # Remove "www." if present to prevent false positive count
            host_clean = hostname[4:] if hostname.startswith("www.") else hostname
            dot_count = host_clean.count(".")
            # A standard domain has 1 dot (domain.com) or 2 dots (domain.co.uk)
            if dot_count > 3:
                triggered_rules.append("EXCESSIVE_SUBDOMAINS")
                heuristic_score += 25
                explanations.append(f"Excessive subdomains ({dot_count} subdomains detected), indicating brand-spoofing nesting.")

        # ----------------------------------------------------
        # 4. Excessive Hyphens
        # Attackers construct hyphenated domain names (e.g. paypal-login-verify-account.com)
        # to circumvent exact-match trademark filters.
        # ----------------------------------------------------
        hyphen_count = hostname.count("-")
        if hyphen_count >= 3:
            triggered_rules.append("EXCESSIVE_HYPHENS")
            heuristic_score += 20
            explanations.append(f"Hostname contains {hyphen_count} hyphens, which is characteristic of phishing domain templates.")

        # ----------------------------------------------------
        # 5. Phishing Keywords
        # Scans the entire URL string for common brand-spoofing or verification terms.
        # ----------------------------------------------------
        matched_keywords = []
        for keyword in cls.PHISHING_KEYWORDS:
            # Check if keyword matches as a distinct word boundary inside hostname or path
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, hostname) or re.search(pattern, path):
                matched_keywords.append(keyword)
                
        if matched_keywords:
            triggered_rules.append("PHISHING_KEYWORDS_FOUND")
            # Score adds 15 per keyword match, capped at 40
            keyword_weight = min(15 * len(matched_keywords), 40)
            heuristic_score += keyword_weight
            explanations.append(f"Phishing-related keywords detected inside URL path/domain: {matched_keywords}.")

        # ----------------------------------------------------
        # 6. Open Redirect Indicators
        # Open-redirect scripts on clean sites are abused to jump users to phishing sites.
        # Check query parameters for URL arguments mapping to redirect keywords.
        # ----------------------------------------------------
        matched_redirect_params = []
        for param in cls.REDIRECT_PARAMS:
            if f"{param}=" in query:
                matched_redirect_params.append(param)
                
        if matched_redirect_params:
            # Confirm if the parameter actually contains a nested URL link
            # Search for http/https or :// patterns inside query string
            if "http" in query or "%3a%2f%2f" in query or "://" in query:
                triggered_rules.append("OPEN_REDIRECT_RISK")
                heuristic_score += 20
                explanations.append(f"Suspicious nested URL detected inside query parameters: '{matched_redirect_params}'. Potential Open Redirect Abuse.")

        # ----------------------------------------------------
        # 7. URL Obfuscation (URL Encoding Abuse)
        # Attackers encode strings to bypass signature checking. Excessive '%' triggers alerts.
        # ----------------------------------------------------
        encoding_count = url_string.count("%")
        if encoding_count > 5:
            triggered_rules.append("EXCESSIVE_URL_ENCODING")
            heuristic_score += 15
            explanations.append(f"Excessive URL encoding ({encoding_count} '%' symbols detected), indicating attempt to obfuscate payloads.")

        # 8. Excessive URL Length
        if len(url_string) > 120:
            triggered_rules.append("EXCESSIVE_URL_LENGTH")
            heuristic_score += 10
            explanations.append(f"URL length is abnormally long ({len(url_string)} characters), which is common in complex phishing redirects.")

        # Cap heuristic score at 100
        heuristic_score = min(heuristic_score, 100)

        return {
            "score": heuristic_score,
            "rules": triggered_rules,
            "explanations": explanations
        }
