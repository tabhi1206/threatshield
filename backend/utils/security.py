import ipaddress
import math

def sanitize_log_data(data: str) -> str:
    """
    CWE-117 (Improper Output Handling for Logs / Log Injection) Mitigation:
    Sanitizes string inputs before writing them to logs.
    Attackers can append carriage returns and line feeds (\r, \n) to forge log entries,
    hiding malicious actions or tricking automated parsing tools.
    
    This function strips newlines and limits character length to prevent log flooding.
    """
    if not data:
        return ""
    # Replace carriage returns and newlines with space to neutralize injection attempts
    sanitized = data.replace("\r", "\\r").replace("\n", "\\n")
    # Limit length of logged payload to prevent Denial of Service (DoS) through oversized logs
    return sanitized[:500]


def is_bogon_or_private_ip(ip_str: str) -> bool:
    """
    Bogon IP & Spoofing Detection:
    A Bogon IP is an IP address that is not officially allocated by IANA or is reserved.
    If an external-facing API receives a request with a source IP belonging to private subnets,
    multicast, or unallocated space, it indicates potential IP spoofing or configuration error.
    
    This checks if the IP belongs to:
    - Private networks (RFC 1918)
    - Loopback addresses
    - Link-local addresses
    - Multicast addresses
    - Reserved addresses
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private      # RFC 1918 (e.g. 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            or ip.is_loopback  # Localhost (e.g. 127.0.0.1)
            or ip.is_link_local # Auto-configuration (e.g. 169.254.0.0/16)
            or ip.is_multicast  # Multicast group (224.0.0.0/4)
            or ip.is_reserved   # Reserved space
        )
    except ValueError:
        # Invalid IP formats are treated as untrusted/suspicious
        return True


def calculate_entropy(text: str) -> float:
    """
    Obfuscation & Shellcode Detection (Shannon Entropy):
    Entropy measures the degree of randomness in a string (0.0 to 8.0 for 8-bit bytes).
    
    In cybersecurity, high entropy in a web payload often signals:
    - Encoded shellcode or binary payloads
    - Encrypted payload fragments
    - Base64/Hex obfuscated commands (commonly used to bypass static web application firewalls)
    
    A standard english phrase usually has an entropy of ~3.0 - 4.5.
    Base64 obfuscated scripts or compressed code will typically have an entropy of 5.5 - 7.5.
    """
    if not text:
        return 0.0
    
    # Calculate frequency of each character in the string
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
        
    length = len(text)
    entropy = 0.0
    
    # Apply Shannon's formula: H = -sum( p(x) * log2( p(x) ) )
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
        
    return round(entropy, 2)
