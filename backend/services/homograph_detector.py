import unicodedata
from typing import Dict, Any, List

class HomographDetector:
    """
    Service to detect Unicode Homograph Spoofing Attacks.
    
    CYBERSECURITY PRINCIPLE: HOMOGRAPH ATTACK
    Attackers register domains using characters from foreign alphabets (Cyrillic, Greek, Hebrew)
    that look identical or highly similar to standard Latin characters.
    For example, "аррӏе.com" contains Cyrillic characters that render in modern browsers
    to look exactly like the legitimate "apple.com". This is used to deceive users in 
    phishing campaigns.
    
    This service analyzes:
    1. IDN (Internationalized Domain Name) Punycode prefixes (e.g., xn--).
    2. Mixed-script violations: blending Cyrillic/Greek and Latin scripts in a single hostname.
    3. Confusable Unicode characters.
    """

    # Map of suspicious Unicode scripts commonly exploited
    SUSPICIOUS_SCRIPTS = ["CYRILLIC", "GREEK", "HEBREW", "CHEROKEE"]

    @classmethod
    def analyze_domain(cls, hostname: str) -> Dict[str, Any]:
        """
        Analyzes a hostname for homograph spoofing indicators.
        
        @param hostname: The domain name to analyze (e.g., 'аррӏе.com').
        @returns: A dictionary with the analysis results and threat score contribution.
        """
        if not hostname:
            return {
                "is_idn": False,
                "is_homograph": False,
                "punycode": "",
                "suspicious_characters": [],
                "explanation": "No hostname provided.",
                "score_contribution": 0
            }

        hostname = hostname.lower().strip()
        is_idn = False
        is_homograph = False
        score_contribution = 0
        explanation = "Domain uses standard Latin character sets."
        suspicious_chars: List[str] = []

        # 1. Check if the domain is Punycode or an Internationalized Domain Name
        try:
            # Encode domain using IDNA codec
            punycode_encoded = hostname.encode("idna").decode("ascii")
            if punycode_encoded != hostname or "xn--" in punycode_encoded:
                is_idn = True
        except Exception:
            # If IDNA encoding fails, it indicates corrupt/abused Unicode sequences
            return {
                "is_idn": True,
                "is_homograph": True,
                "punycode": "invalid-idna",
                "suspicious_characters": ["unknown"],
                "explanation": "Domain failed standard IDNA Punycode conversion. High probability of spoofing/exploit.",
                "score_contribution": 85
            }

        # 2. Inspect characters for script mixing
        # We classify the scripts of all characters inside the hostname.
        detected_scripts = set()
        
        for char in hostname:
            # Skip dots, dashes, and numbers which are benign in hostnames
            if char in [".", "-", "_"] or char.isdigit():
                continue
                
            try:
                char_name = unicodedata.name(char)
                # Extract script category (e.g., 'LATIN SMALL LETTER A' -> 'LATIN')
                script = char_name.split()[0] if char_name else "UNKNOWN"
                detected_scripts.add(script)
                
                # Check if the script is in our suspicious list or not Latin
                if any(suspicious in char_name for suspicious in cls.SUSPICIOUS_SCRIPTS):
                    suspicious_chars.append(f"{char} (U+{ord(char):04X} - {script})")
            except ValueError:
                # Character has no name, indicating unallocated/abnormal Unicode symbol
                suspicious_chars.append(f"{char} (U+{ord(char):04X} - UNKNOWN)")
                detected_scripts.add("UNKNOWN")

        # 3. Apply Cybersecurity Rules:
        # Rule A: If there's an active IDN AND we detect mixed scripts (e.g., Latin + Cyrillic), 
        # it is a high-confidence homograph indicator.
        if is_idn:
            if len(detected_scripts) > 1 and ("LATIN" in detected_scripts or "COMMON" in detected_scripts):
                is_homograph = True
                score_contribution = 90
                explanation = f"CRITICAL: Unicode Homograph Spoofing detected. Domain combines multiple scripts: {list(detected_scripts)}. Punycode representation is '{punycode_encoded}'."
            else:
                # Legit IDN (e.g., a fully Cyrillic website for international users: e.g. .рф)
                is_homograph = False
                score_contribution = 15  # Slightly elevated risk due to generic IDN usage in campaigns
                explanation = f"Internationalized Domain Name (IDN) detected. Punycode: '{punycode_encoded}'. All characters use a single localized character set."
        
        # Rule B: Mixed script check without explicit IDN conversion (backup heuristic check)
        elif len(detected_scripts) > 1 and any(s in detected_scripts for s in cls.SUSPICIOUS_SCRIPTS):
            is_homograph = True
            score_contribution = 75
            explanation = f"WARNING: Suspicious script mixing detected inside hostname without standard IDNA wrapper. Scripts: {list(detected_scripts)}."

        return {
            "is_idn": is_idn,
            "is_homograph": is_homograph,
            "punycode": punycode_encoded if is_idn else hostname,
            "suspicious_characters": suspicious_chars[:10], # Truncate list to prevent bloated database payload
            "explanation": explanation,
            "score_contribution": score_contribution
        }
