from typing import Dict, Any, List
from app.utils.safe_http import safe_get

# Strict allowlist - No fuzzing allowed
ALLOWLISTED_FILES = [
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    "ads.txt"
]

async def check_public_files(domain: str) -> Dict[str, Any]:
    """
    Checks for the existence of standard public files.
    Passive/Safe: Only checks a strict allowlist of standard paths.
    """
    base_url = f"https://{domain}"
    results = {
        "found": [],
        "missing": [],
        "interesting_findings": []
    }
    
    # Try HTTPS first (safe_get handles this typically, but we construct full URLs here)
    
    for filename in ALLOWLISTED_FILES:
        url = f"{base_url}/{filename}"
        
        # We process sequentially to avoid aggressive rate limiting or triggering WAFs
        # (Though safe_get uses limits, parallel requests might still look aggressive)
        response = await safe_get(url)
        
        if "error" not in response and response.get("status_code") == 200:
            results["found"].append(filename)
            
            content = response.get("content_text", "")
            
            # Basic analysis
            if filename == "robots.txt":
                if "Disallow: /admin" in content or "Disallow: /control" in content:
                    results["interesting_findings"].append(f"robots.txt hides admin paths")
            
            if "security.txt" in filename:
                 results["interesting_findings"].append(f"security.txt present (VDP enabled?)")

        else:
             results["missing"].append(filename)
             
    return results
