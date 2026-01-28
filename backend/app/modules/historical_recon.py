from typing import Dict, Any, List, Set
from urllib.parse import urlparse
from app.utils.safe_http import safe_get
import re

# Limit URL results
MAX_HISTORICAL_URLS = 50

async def check_historical_data(domain: str) -> Dict[str, Any]:
    """
    Analyzes archived versions of the website using Archive.org CDX API.
    Passive analysis only.
    """
    # CDX API to list unique URLs captured for the domain
    # collapse=urlkey filters out duplicates of the same URL (revisions) -> distinct paths
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
        f"&output=json&fl=original,timestamp,mimetype,statuscode"
        f"&collapse=urlkey&limit={MAX_HISTORICAL_URLS}"
    )
    
    results = {
        "source": "wayback_machine",
        "historical_endpoints": [],
        "tech_stack_history": [],
        "interesting_files": []
    }
    
    try:
        response = await safe_get(cdx_url)
        
        if "error" not in response and response.get("status_code") == 200:
            import json
            try:
                content = response.get("content_text", "[]")
                data = json.loads(content)
                
                # CDX output is list of lists. First row is header usually if not json output?
                # With output=json, it is [[key, key], [val, val]]
                if not data or not isinstance(data, list):
                    return results
                
                # Check for header row
                header = data[0] if len(data) > 0 else []
                rows = data[1:] if len(data) > 1 else []
                
                tech_set: Set[str] = set()
                
                for row in rows:
                    # fl=original,timestamp,mimetype,statuscode
                    # simplistic mapping, might vary slightly
                    if len(row) < 1:
                        continue
                        
                    original_url = row[0]
                    # timestamps = row[1]
                    # mimetype = row[2]
                    
                    parsed = urlparse(original_url)
                    path = parsed.path
                    
                    if path == "/" or not path:
                        continue

                    # 1. Collect Endpoints
                    if path not in results["historical_endpoints"]:
                        results["historical_endpoints"].append(path)
                        
                    # 2. Detect Tech Stack History (Extensions)
                    # Heuristic: Check extensions
                    ext_patterns = {
                        r'\.php$': 'PHP',
                        r'\.asp$': 'ASP',
                        r'\.aspx$': 'ASP.NET',
                        r'\.jsp$': 'Java/JSP',
                        r'\.do$': 'Java/Struts',
                        r'\.cfm$': 'ColdFusion',
                        r'\.pl$': 'Perl',
                        r'\.py$': 'Python',
                        r'\.rb$': 'Ruby',
                        r'wp-content': 'WordPress',
                        r'wp-includes': 'WordPress',
                        r'drupal': 'Drupal',
                        r'joomla': 'Joomla'
                    }
                    
                    for pattern, tech in ext_patterns.items():
                        if re.search(pattern, path, re.IGNORECASE):
                            tech_set.add(tech)
                            
                    # 3. Detect Interesting/Removed Files
                    # Look for sensitive extensions in history
                    sensitive_exts = ['.bak', '.sql', '.config', '.old', '.backup', '.log', '.env']
                    for sens in sensitive_exts:
                         if path.endswith(sens):
                             results["interesting_files"].append(path)

                results["tech_stack_history"] = list(tech_set)
                
            except Exception:
                pass
                
    except Exception:
        pass
        
    return results
