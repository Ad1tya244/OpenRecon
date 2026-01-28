from typing import Dict, Any, List
from app.utils.safe_http import safe_head, safe_get

# Strict allowlist - No scanning/fuzzing
ALLOWLISTED_PATHS = [
    "/assets/",
    "/uploads/",
    "/static/"
]

async def check_directory_exposure(domain: str) -> Dict[str, Any]:
    """
    Checks for directory listing exposure on specific sensitive paths.
    1. Sends HEAD request.
    2. If 200 OK, sends GET request.
    3. Checks body for directory listing signatures ("Index of", etc).
    """
    base_url = f"https://{domain}"
    results = {
        "exposed_directories": [],
        "protected_directories": [],
        "missing_directories": []
    }
    
    # Try HTTPS
    
    for path in ALLOWLISTED_PATHS:
        url = f"{base_url}{path}"
        
        # 1. HEAD Request
        head_resp = await safe_head(url)
        
        if "error" in head_resp:
             results["missing_directories"].append(path) # Treat network error as missing for passive recon
             continue
             
        status = head_resp.get("status_code", 0)
        
        if status == 403 or status == 401:
             results["protected_directories"].append(path)
        elif status == 200:
            # 2. GET Request (only if 200) to confirm listing
            get_resp = await safe_get(url)
            if "error" not in get_resp and get_resp.get("status_code") == 200:
                content = get_resp.get("content_text", "")
                
                # Check for signatures
                signatures = [
                    "Index of /",
                    "Directory listing for",
                    "Parent Directory"
                ]
                
                is_listing = False
                for sig in signatures:
                    if sig in content:
                        is_listing = True
                        break
                
                if is_listing:
                    results["exposed_directories"].append(path)
                else:
                    # 200 but not a listing (maybe empty page or default app page)
                    # We can consider it found but not exposed
                    pass
        else:
             results["missing_directories"].append(path) # 404, etc.

    return results
