import urllib.request
from urllib.parse import urlparse
import ipaddress
import socket
from typing import Dict, Any, List

class RedirectAnalyzer:
    """
    Redirect Intelligence and URL Expansion service.
    
    CYBERSECURITY PRINCIPLE: REDIRECT ABUSE & LINK OBFUSCATION
    Phishers use URL shorteners (e.g. bit.ly, tinyurl) or multi-hop redirect pages
    (open redirects) to conceal their destination URL. This makes static email/message filters
    believe the link is safe. The victim is then bounced across several hosts until landing on
    the phishing site.
    
    SECURITY MEASURES:
    1. SSRF (Server-Side Request Forgery) Prevention: Before following any redirect hop, 
       we resolve the target domain's IP and verify it does NOT belong to private (RFC 1918), 
       loopback, or link-local subnets (e.g., blocking attempts to query 169.254.169.254).
    2. Infinite Loop Guard: Tracks visited URLs. If a URL is repeated, aborts and flags a loop.
    3. Strict Timeouts: Set at 2.0s per hop to prevent Denial of Service (DoS) thread blocking.
    """

    # List of known URL shorteners to flag for active expansion
    SHORTENERS = [
        "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "shorturl.at", 
        "rebrand.ly", "is.gd", "tiny.cc", "lnkd.in", "ow.ly"
    ]

    @classmethod
    def resolve_redirects(cls, initial_url: str) -> Dict[str, Any]:
        """
        Follows the redirection path of a URL up to a maximum depth.
        
        @param initial_url: The starting URL.
        @returns: A dictionary detailing the expanded URL, redirect history, and threat score.
        """
        history: List[str] = [initial_url]
        current_url = initial_url
        max_hops = 5
        timeout = 2.0
        redirect_score = 0
        explanations: List[str] = []
        is_shortened = False

        # Check if the initial URL uses a known shortener domain
        try:
            parsed_init = urlparse(initial_url)
            init_host = (parsed_init.hostname or "").lower()
            if init_host in cls.SHORTENERS or init_host.startswith("www.") and init_host[4:] in cls.SHORTENERS:
                is_shortened = True
        except Exception:
            pass

        # Follow redirects in a secure loop
        for hop in range(max_hops):
            parsed_url = urlparse(current_url)
            
            # 1. Enforce Protocol Constraints
            if parsed_url.scheme not in ["http", "https"]:
                explanations.append(f"Redirect terminated: Unsupported protocol scheme '{parsed_url.scheme}'.")
                break

            # 2. SSRF Protection: Resolve Host to IP and validate it is public
            hostname = parsed_url.hostname
            if not hostname:
                break
                
            try:
                # Resolve hostname to IP address (blocking local/private range connections)
                ip_addr = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip_addr)
                
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    explanations.append(f"SSRF BLOCKADE: Redirect chain attempted to pivot to private IP range ({ip_addr}). Inspection aborted.")
                    redirect_score += 65
                    break
            except socket.gaierror:
                # Hostname fails DNS resolution
                explanations.append(f"DNS Resolution failed for host: '{hostname}'. Terminating redirect chain.")
                break

            # 3. Perform safe HTTP HEAD request to check redirection header (Location)
            # We use HEAD instead of GET to minimize payload transmission (saves server bandwidth)
            req = urllib.request.Request(
                current_url,
                method="HEAD",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatShield/1.0"}
            )

            try:
                # Create custom Redirect handler to PREVENT default auto-follow.
                # We want to manually intercept and inspect each hop in our loop.
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                        # Block automatic redirects and return the response object instead
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)
                with opener.open(req, timeout=timeout) as response:
                    status_code = response.status
                    
                    # Intercept standard HTTP redirect statuses (301, 302, 303, 307, 308)
                    if status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location")
                        if not location:
                            break

                        # Build absolute URL path if redirect header location is relative
                        if not urlparse(location).scheme:
                            location = urllib.parse.urljoin(current_url, location)

                        # Loop check: Prevent circular redirect attacks
                        if location in history:
                            explanations.append(f"Redirect Loop detected: '{location}' has already been processed.")
                            redirect_score += 40
                            break

                        # Append to history and shift current scope
                        history.append(location)
                        current_url = location
                        
                        # Double check if any intermediate hop is a shortener
                        hop_host = (urlparse(location).hostname or "").lower()
                        if hop_host in cls.SHORTENERS:
                            is_shortened = True
                    else:
                        # Request is loaded and no further redirect header is present
                        break
            except Exception as request_err:
                # If network fails (timeout/refused), log error and exit loop
                explanations.append(f"Network request failed during expansion: {str(request_err)}")
                break
        
        # Determine redirect scores based on depth and obfuscation flags
        redirect_depth = len(history) - 1
        
        if redirect_depth > 0:
            if is_shortened:
                redirect_score += 15
                explanations.append(f"URL concealment detected: Link was passed through shortener system (expanded from '{initial_url}').")
            if redirect_depth >= 3:
                redirect_score += 30
                explanations.append(f"Suspicious redirect depth: Request hopped {redirect_depth} times before landing on destination.")
            else:
                explanations.append(f"Redirect chain resolved: {redirect_depth} redirect hop(s) detected.")

        return {
            "expanded_url": current_url,
            "redirect_history": history,
            "redirect_depth": redirect_depth,
            "is_shortened": is_shortened,
            "score": min(redirect_score, 100),
            "explanations": explanations
        }
