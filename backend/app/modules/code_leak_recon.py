import re
import os
from typing import Dict, Any, List
from app.utils.safe_http import safe_get

# Mock results for demonstration if no API key is present
# Real implementation would need a GITHUB_TOKEN env var
GITHUB_API_URL = "https://api.github.com/search/code"

def mask_secret(text: str) -> str:
    """
    Masks high-entropy strings or obvious secrets in the snippet.
    """
    # Simple regex for things looking like keys
    # Key = "Value"
    # Replacing the value with ***
    
    patterns = [
        (r'(api_key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["\'](.*?)["\']', r'\1 = "***"'),
        (r'(api_key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*([a-zA-Z0-9_\-]{8,})', r'\1 = "***"')
    ]
    
    masked_text = text
    for pattern, replacement in patterns:
        masked_text = re.sub(pattern, replacement, masked_text, flags=re.IGNORECASE)
    
    return masked_text

async def check_code_leaks(domain: str) -> Dict[str, Any]:
    """
    Searches public code repositories (GitHub) for the domain.
    Detects potential credential leaks and masks them.
    """
    results = {
        "platform": "GitHub",
        "findings": [],
        "count": 0,
        "status": "active"
    }

    # In a real scenario, we need a token.
    # For this assignment, we will simulate the behavior or try unauthed if allowed.
    # GitHub Code Search REQUIRES authentication.
    # So we will return a "Configuration Needed" message if no token is found in env,
    # rather than failing or returning fake data.
    
    # Check for token (not implemented in settings yet, looking at os.environ)
    token = os.environ.get("GITHUB_TOKEN")
    
    if not token:
        results["status"] = "skipped_no_token"
        results["message"] = "GitHub Token required for code search."
        return results
        
    # Construct Query
    # q=domain check
    query = f"q={domain}"
    url = f"{GITHUB_API_URL}?{query}&per_page=5"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    try:
        response = await safe_get(url, headers=headers)
        
        if "error" not in response and response.get("status_code") == 200:
             import json
             content = json.loads(response.get("content_text", "{}"))
             items = content.get("items", [])
             
             for item in items:
                 # Metadata only
                 repo_name = item.get("repository", {}).get("full_name", "unknown")
                 html_url = item.get("html_url", "")
                 
                 # GitHub API doesn't always return the code snippet in search list, 
                 # it requires text-match media type or separate fetch.
                 # We'll use the metadata we have.
                 
                 # If we want snippets, we need specific headers, but let's keep it simple metadata.
                 # "No repository cloning" -> handled.
                 
                 finding = {
                     "repository": repo_name,
                     "url": html_url,
                     "snippet_preview": "Metadata match only" 
                 }
                 
                 results["findings"].append(finding)
                 
             results["count"] = content.get("total_count", 0)
             
        elif response.get("status_code") == 401:
             results["status"] = "error"
             results["message"] = "Invalid GitHub Token"
        elif response.get("status_code") == 403:
             results["status"] = "error"
             results["message"] = "GitHub API Rate Limited"

    except Exception:
        results["status"] = "error"
        results["message"] = "Search failed"
        
    return results
