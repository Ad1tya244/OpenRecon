import httpx
import json
from typing import List, Dict, Any
from app.utils.safe_http import safe_get

MAX_SUBDOMAINS = 100

SENSITIVE_KEYWORDS = {
    "dev": "Development Environment",
    "staging": "Staging Environment",
    "stg": "Staging Environment",
    "test": "Test Environment",
    "uat": "UAT Environment",
    "admin": "Administrative Interface",
    "api": "API Endpoint",
    "internal": "Internal Infrastructure",
    "vpn": "Remote Access",
    "demo": "Demo Environment",
    "beta": "Beta Environment"
}

async def enumerate_subdomains(domain: str) -> Dict[str, Any]:
    """
    Enumerates subdomains using crt.sh (Certificate Transparency logs).
    Passive technique.
    Returns structured data with environment analysis.
    """
    crt_sh_url = f"https://crt.sh/?q=%.{domain}&output=json"
    unique_subdomains = set()
    cleaned_results = []
    
    # Sources
    sources = [
        {"name": "crt.sh", "url": f"https://crt.sh/?q=%.{domain}&output=json"},
        {"name": "hackertarget", "url": f"https://api.hackertarget.com/hostsearch/?q={domain}"}
    ]

    for source in sources:
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                response = await client.get(source["url"])
            
            if response.status_code == 200:
                if source["name"] == "crt.sh":
                    try:
                        content = response.text
                        data = json.loads(content)
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for name in name_value.split("\n"):
                                name = name.lower().strip()
                                if "*" not in name and name.endswith(domain):
                                    unique_subdomains.add(name)
                        # If we got data, break loop? 
                        # crt.sh is usually best. If it works, we can stop or combine. 
                        # Let's combine if possible, but for speed maybe stop if > 0.
                        if unique_subdomains:
                            break
                    except Exception:
                        pass
                
                elif source["name"] == "hackertarget":
                    # format: hostname,ip\n
                    lines = response.text.split("\n")
                    for line in lines:
                         parts = line.split(",")
                         if len(parts) >= 1:
                             name = parts[0].lower().strip()
                             if name.endswith(domain):
                                 unique_subdomains.add(name)
        except Exception:
            continue
        
    # Sort and Limit
    sorted_subs = sorted(list(unique_subdomains))[:MAX_SUBDOMAINS]
    
    # Analysis
    for sub in sorted_subs:
        flags = []
        context = "Public"
        is_interesting = False
        
        # Breakdown subdomain parts extracted from the domain
        # e.g. dev.api.example.com -> [dev, api]
        prefix = sub.replace(f".{domain}", "")
        parts = prefix.split(".")
        
        for part in parts:
            if part in SENSITIVE_KEYWORDS:
                flags.append(SENSITIVE_KEYWORDS[part])
                is_interesting = True
                context = "Potentially Sensitive"
        
        cleaned_results.append({
            "hostname": sub,
            "flags": flags,
            "context": context,
            "is_interesting": is_interesting
        })

    return {
        "subdomains": cleaned_results,
        "count": len(cleaned_results),
        "limit_reached": len(unique_subdomains) > MAX_SUBDOMAINS
    }
