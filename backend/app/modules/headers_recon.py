import httpx
from typing import Dict, Any
from app.utils.safe_http import safe_get

async def analyze_headers(domain: str) -> Dict[str, Any]:
    """
    Analyzes HTTP response headers for security configurations.
    Uses safe_get for SSRF protection.
    """
    # Force HTTPS for the scan default, or we could try both.
    url = f"https://{domain}"
    results = {
        "missing_security_headers": [],
        "headers": {}
    }
    
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    
    try:
        response_data = await safe_get(url)
        
        if "error" in response_data:
             return {"error": response_data["error"]}

        server_headers = response_data.get("headers", {})
        results["headers"] = server_headers
        
        for header in security_headers:
            # Case insensitive check might be needed, but usually these are standard
            # httpx/safe_get returns dict where keys might be strict?
            # Replicating strict check.
            found = False
            for k in server_headers.keys():
                if k.lower() == header.lower():
                    found = True
                    break
            if not found:
                results["missing_security_headers"].append(header)
                
        # Helper for case-insensitive get
        def get_header(name):
            for k, v in server_headers.items():
                if k.lower() == name.lower():
                    return v
            return "Unknown"

        results["server"] = get_header("server")
        results["powered_by"] = get_header("x-powered-by")
        
        return results
        
    except Exception as e:
        return {"error": "Analysis failed"}
