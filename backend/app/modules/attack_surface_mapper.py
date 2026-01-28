from typing import Dict, Any, List
from app.modules import risk_scoring

def map_attack_surface(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates results from various reconnaissance modules to build
    a structured attack surface map and highlight high-risk exposures.
    
    Input: Dictionary containing results from all scan modules.
    Output: Structured map with 'summary', 'attack_vectors', and 'risk_score'.
    
    Security: Read-only processing. No network calls.
    """
    
    surface_map = {
        "summary": {
            "total_subdomains": 0,
            "open_ports": [], # We don't have port scan module explicit yet, but maybe inferred?
            "critical_risks": 0,
            "medium_risks": 0
        },
        "assets": {
            "domains": [],
            "ips": [],
            "technologies": []
        },
        "exposure_points": [],
        "risk_assessment": {
            "score": 100, # Start high, deduct for risks
            "grade": "A"
        }
    }
    
    risks = []

    # 1. Asset Inventory
    # 1. Asset Inventory
    # Subdomains
    sub_data = scan_data.get("subdomains", {})
    if isinstance(sub_data, list):
         # Legacy or fallback
         subdomains = sub_data
    else:
         # New dict format
         subdomains = [s.get("hostname") for s in sub_data.get("subdomains", [])]

    surface_map["summary"]["total_subdomains"] = len(subdomains)
    surface_map["assets"]["domains"] = subdomains
    
    # IPs (from DNS)
    dns_data = scan_data.get("dns", {})
    ips = set()
    if isinstance(dns_data, dict):
        for record_type, records in dns_data.items():
            if record_type in ["A", "AAAA"]:
                for rec in records:
                    ips.add(rec)
    surface_map["assets"]["ips"] = list(ips)
    
    # Technologies
    tech_data = scan_data.get("tech", {})
    if isinstance(tech_data, dict):
        surface_map["assets"]["technologies"] = tech_data.get("frameworks", []) + [tech_data.get("server")]
        # Filter None
        surface_map["assets"]["technologies"] = [t for t in surface_map["assets"]["technologies"] if t]

    # 2. Risk Correlation & High-Risk Exposure Points
    # Use dedicated risk scoring module
    scoring_result = risk_scoring.calculate_risk_score(scan_data)
    
    # Populate findings/risks from the scoring result
    risks = scoring_result.get("risks", [])
    
    surface_map["risk_assessment"]["score"] = scoring_result.get("score", 100)
    surface_map["risk_assessment"]["grade"] = scoring_result.get("grade", "A")
    surface_map["risks"] = risks

    # Extract exposure points for map based on risks
    # Re-iterate to fill exposure_points specifically for UI map
    
    # Directory Exposure
    dir_Exp = scan_data.get("directory_exposure", {})
    if isinstance(dir_Exp, dict):
        exposed = dir_Exp.get("exposed_directories", [])
        if exposed:
            surface_map["exposure_points"].append({"type": "Directory Listing", "paths": exposed})
            surface_map["summary"]["critical_risks"] += 1

    # Code Leaks
    leaks = scan_data.get("code_leaks", {})
    if isinstance(leaks, dict) and leaks.get("count", 0) > 0:
         surface_map["exposure_points"].append({"type": "Code Leak", "details": "GitHub Mentions"})
         surface_map["summary"]["critical_risks"] += 1
         
    # SSL Criticals
    ssl_data = scan_data.get("ssl", {})
    if isinstance(ssl_data, dict) and ssl_data.get("is_expired"):
         surface_map["summary"]["critical_risks"] += 1
         
    surface_map["summary"]["medium_risks"] = len([r for r in risks if r["severity"] == "Medium"])
    
    return surface_map
