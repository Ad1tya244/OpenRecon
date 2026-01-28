from typing import Dict, Any, List
import re
from app.utils.safe_http import safe_get

# Thresholds for flagging "Outdated" or "Legacy"
# This is a heuristic/simplified list for the assignment
LEGACY_THRESHOLDS = {
    "PHP": (8, 0),       # Flag < 8.0
    "Apache": (2, 4),    # Flag < 2.4
    "nginx": (1, 18),    # Flag < 1.18
    "IIS": (10, 0),      # Flag < 10.0 (Windows Server 2016+)
    "Python": (3, 8)     # Flag < 3.8
}

def parse_version(banner: str) -> str:
    """
    Extracts version string like '1.2.3' from a banner.
    """
    if not banner:
        return ""
    # Look for patterns like "Name/1.2.3" or "Name 1.2.3"
    match = re.search(r'[\/\s](\d+\.\d+(?:\.\d+)?)', banner)
    if match:
        return match.group(1)
    return ""

def check_legacy(tech_name: str, version_str: str) -> bool:
    """
    Returns True if version is considered legacy/outdated.
    """
    if not version_str:
        return False
        
    threshold = None
    # Find matching threshold key (case insensitive partial match)
    for key, val in LEGACY_THRESHOLDS.items():
        if key.lower() in tech_name.lower():
            threshold = val
            break
            
    if not threshold:
        return False
        
    try:
        parts = [int(p) for p in version_str.split('.')]
        # Pad with 0
        while len(parts) < 2:
            parts.append(0)
            
        t_major, t_minor = threshold
        
        if parts[0] < t_major:
            return True
        if parts[0] == t_major and parts[1] < t_minor:
            return True
    except Exception:
        pass
        
    return False

async def get_tech_fingerprint(domain: str) -> Dict[str, Any]:
    """
    Identifies technologies and analyzes security posture based on HTTP headers.
    Passive analysis only. Returns structured data with legacy flags.
    """
    url = f"https://{domain}"
    
    results = {
        "server": None,
        "frameworks": [],
        "proxies": [],
        "security_headers": {},
        "missing_security_headers": [],
        "os_hint": "Unknown",
        "flags": []
    }
    
    # 1. Fetch Headers Securely
    response = await safe_get(url)
    
    if "error" in response:
        # Fallback to HTTP
        url = f"http://{domain}"
        response = await safe_get(url)
        if "error" in response:
             return {"error": "Could not fetch headers (Target unreachable or blocked)"}

    headers = response.get("headers", {})
    # Normalize keys to lowercase for easier lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    # 2. Server Detection
    if "server" in headers_lower:
        server_header = headers_lower["server"]
        results["server"] = server_header
        
        # OS Detection from Server Header
        if "ubuntu" in server_header.lower():
            results["os_hint"] = "Ubuntu Linux"
            results["frameworks"].append("Ubuntu")
        elif "debian" in server_header.lower():
            results["os_hint"] = "Debian Linux"
            results["frameworks"].append("Debian")
        elif "centos" in server_header.lower():
            results["os_hint"] = "CentOS Linux"
            results["frameworks"].append("CentOS")
        elif "win32" in server_header.lower() or "microsoft-iis" in server_header.lower():
            results["os_hint"] = "Windows Server"
            
        # Legacy Check
        version = parse_version(server_header)
        if version:
            if "apache" in server_header.lower():
                if check_legacy("Apache", version):
                    results["flags"].append(f"Outdated Apache detected (v{version})")
            elif "nginx" in server_header.lower():
                if check_legacy("nginx", version):
                    results["flags"].append(f"Outdated Nginx detected (v{version})")
            elif "iis" in server_header.lower():
                if check_legacy("IIS", version):
                    results["flags"].append(f"Legacy IIS detected (v{version})")
    
    # 3. Framework/Tech Headers
    
    # X-Powered-By
    if "x-powered-by" in headers_lower:
        val = headers_lower["x-powered-by"]
        results["frameworks"].append(val)
        
        # PHP Version Check
        if "php" in val.lower():
            v = parse_version(val)
            if v and check_legacy("PHP", v):
                results["flags"].append(f"Outdated PHP version (v{v})")
        
        # ASP.NET Check
        if "asp.net" in val.lower():
            results["frameworks"].append("ASP.NET")
            results["os_hint"] = "Windows Server"

    # Other Headers
    if "x-generator" in headers_lower:
        results["frameworks"].append(headers_lower["x-generator"])
    if "x-aspnet-version" in headers_lower:
        results["frameworks"].append("ASP.NET")
        results["os_hint"] = "Windows Server"
    if "x-runtime" in headers_lower:
        # Common in Ruby/Rails/Node
        pass
    
    # Cookie Analysis for Frameworks
    # Note: safe_get returns headers dict, if multiple Set-Cookie, usage depends on httpx. 
    # Usually we get one string or list. We'll search the string representation.
    # Looking for keys in the raw header dump might be safer if we had it, but here we search all values.
    # Actually, simpler: check keys of headers_lower for known framework headers?
    # No, check values of "set-cookie" if exists.
    
    if "set-cookie" in headers_lower:
        cookie_val = str(headers_lower["set-cookie"])
        if "PHPSESSID" in cookie_val:
            results["frameworks"].append("PHP")
        if "JSESSIONID" in cookie_val:
            results["frameworks"].append("Java")
        if "ASP.NET_SessionId" in cookie_val:
            results["frameworks"].append("ASP.NET")
            results["os_hint"] = "Windows Server"
        if "csrftoken" in cookie_val:
            results["frameworks"].append("Django (Python)")
        if "rack.session" in cookie_val:
            results["frameworks"].append("Ruby on Rails")
        if "laravel_session" in cookie_val:
             results["frameworks"].append("Laravel (PHP)")

    # 4. Proxy/CDN Detection
    if "via" in headers_lower:
        results["proxies"].append(headers_lower["via"])
    if "x-cache" in headers_lower:
        results["proxies"].append(headers_lower["x-cache"])
    if "cf-ray" in headers_lower:
        results["proxies"].append("Cloudflare")
    if "server" in results and results["server"] and "cloudflare" in results["server"].lower():
        if "Cloudflare" not in results["proxies"]:
            results["proxies"].append("Cloudflare")

    # 5. Security Headers Analysis
    security_headers_list = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection"
    ]
    
    for sec_header in security_headers_list:
        if sec_header.lower() in headers_lower:
            results["security_headers"][sec_header] = headers_lower[sec_header.lower()]
        else:
            results["missing_security_headers"].append(sec_header)
            
    # Clean up lists
    results["frameworks"] = list(set(results["frameworks"]))
    results["proxies"] = list(set(results["proxies"]))
    
    return results
