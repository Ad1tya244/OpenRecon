from typing import Dict, Any, List
from app.modules.confidence_evidence_engine import ConfidenceEngine

def generate_intelligence(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Converts raw OSINT reconnaissance data into meaningful, correlated attack-surface intelligence.
    
    CORE RESPONSIBILITIES:
    1. Correlate findings across multiple layers.
    2. Detect and classify intelligence patterns.
    3. Ensure correlations are explainable.
    
    Inputs: Normalized scan data dict.
    Outputs: List of intelligence findings.
    """
    findings = []
    
    # 1. Exposed Administrative Interfaces
    admin_finding = _detect_admin_exposure(scan_data)
    if admin_finding:
        findings.append(admin_finding)
        
    # 2. Weak Email Security Posture
    email_finding = _assess_email_posture(scan_data)
    if email_finding:
        findings.append(email_finding)
        
    # 3. Legacy Application Exposure
    legacy_finding = _detect_legacy_exposure(scan_data)
    if legacy_finding:
        findings.append(legacy_finding)

    # 4. Public Data Leakage (Bonus based on prompt requirements about exposure clusters)
    leak_finding = _detect_data_leakage(scan_data)
    if leak_finding:
        findings.append(leak_finding)
        
    return ConfidenceEngine.enrich_findings(findings)

def _detect_admin_exposure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates subdomains, ports, and tech to find exposed admin surfaces.
    """
    signals = []
    
    # Signal A: Subdomains
    subdomains = data.get("subdomains", [])
    if isinstance(subdomains, dict): 
        subdomains = subdomains.get("subdomains", [])
    
    subs_list = []
    if isinstance(subdomains, list):
        for s in subdomains:
            if isinstance(s, dict): subs_list.append(s.get("hostname", ""))
            elif isinstance(s, str): subs_list.append(s)

    admin_keywords = ["admin", "vpn", "dashboard", "portal", "internal", "manage", "control", "private"]
    exposed_subs = [s for s in subs_list if any(k in s.lower() for k in admin_keywords)]
    
    if exposed_subs:
        signals.append(f"High-risk subdomains detected: {', '.join(exposed_subs[:5])}" + ("..." if len(exposed_subs)>5 else ""))

    # Signal B: Ports
    ports_data = data.get("ports", {})
    open_ports = ports_data.get("open_ports", []) if isinstance(ports_data, dict) else []
    
    # Sensitive management ports
    mgmt_ports = [22, 23, 3389, 5900, 8443, 8080, 9090, 10000] 
    found_mgmt_ports = [p for p in open_ports if p.get("port") in mgmt_ports]
    
    if found_mgmt_ports:
        port_list = [f"{p.get('port')}/{p.get('service')}" for p in found_mgmt_ports]
        signals.append(f"Management ports exposed to internet: {', '.join(port_list)}")

    if not signals:
        return None

    # Determine Severity based on convergence
    # If both subdomains and ports are found -> High
    severity = "High" if (exposed_subs and found_mgmt_ports) else "Medium"
    
    return {
        "title": "Exposed Administrative Interface",
        "description": "Critical administrative or internal operational surfaces are exposed to the public internet. This convergence of sensitive subdomains and management ports significantly increases the risk of unauthorized access.",
        "severity": severity,
        "signals": signals
    }

def _assess_email_posture(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates DNS and Whois to assess email security.
    """
    signals = []
    dns = data.get("dns", {})
    if not isinstance(dns, dict): return None
    
    email_sec = dns.get("email_security", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})
    
    # Signal A: SPF
    if not spf.get("present"):
        signals.append("SPF Record: Missing completely.")
    elif spf.get("status") == "softfail" or "~all" in spf.get("record", ""):
        signals.append("SPF Record: Permissive configuration (~all detected).")

    # Signal B: DMARC
    if not dmarc.get("present"):
        signals.append("DMARC Record: Missing completely.")
    elif dmarc.get("policy") == "none":
        signals.append("DMARC Policy: Set to 'none' (Monitoring only, no enforcement).")

    if not signals:
        return None

    severity = "Medium"
    if "Missing completely" in str(signals) and len(signals) >= 2:
        severity = "High"

    return {
        "title": "Weak Email Security Posture",
        "description": "The domain lacks strict email authentication controls (SPF/DMARC), creating a high risk of domain spoofing and phishing attacks impersonating the organization.",
        "severity": severity,
        "signals": signals
    }

def _detect_legacy_exposure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates Tech stack and SSL to find legacy systems.
    """
    signals = []
    tech = data.get("tech", {})
    if not isinstance(tech, dict): return None
    
    # Signal A: Server Version (Heuristic)
    server = tech.get("server", "")
    if server:
        # Simple string matching for common legacy signatures
        legacy_sigs = ["apache/2.2", "nginx/1.10", "iis/6.0", "iis/7.0", "iis/7.5", "php/5"]
        if any(sig in server.lower() for sig in legacy_sigs):
             signals.append(f"Outdated Server Software: {server}")

    # Signal B: SSL
    ssl_data = data.get("ssl", {})
    if isinstance(ssl_data, dict):
        if ssl_data.get("is_expired"):
            signals.append("SSL Certificate: Expired")
        # In a real deep dive, we'd check Protocol versions (TLS 1.0/1.1)
        
    # Signal C: Headers
    headers_data = data.get("headers", {})
    if isinstance(headers_data, dict):
        x_powered = headers_data.get("headers", {}).get("x-powered-by", "")
        if "php/5" in x_powered.lower() or "asp.net" in x_powered.lower():
             # Just presence isn't critical, but noted
             pass

    if not signals:
        return None

    return {
        "title": "Legacy Application Exposure",
        "description": "Evidence of end-of-life or outdated infrastructure components was detected. These systems often harbor unpatched vulnerabilities.",
        "severity": "Medium",
        "signals": signals
    }

def _detect_data_leakage(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlates code leaks and public files.
    """
    signals = []
    
    # Signal A: GitHub Leaks
    leaks = data.get("code_leaks", {})
    if isinstance(leaks, dict) and leaks.get("count", 0) > 0:
        signals.append(f"Code Repositories: {leaks.get('count')} potential leaks found on GitHub.")
        
    # Signal B: Public Files
    pub = data.get("public_files", {})
    if isinstance(pub, dict):
        interesting = pub.get("interesting_findings", [])
        if interesting:
            signals.extend([f"Public File: {x}" for x in interesting])
            
    # Signal C: Directory Listing
    dir_exp = data.get("directory_exposure", {})
    if isinstance(dir_exp, dict):
        exposed = dir_exp.get("exposed_directories", [])
        if exposed:
            signals.append(f"Directory Indexing: Enabled on {len(exposed)} paths.")

    if not signals:
        return None

    return {
        "title": "Data Leakage & Information Disclosure",
        "description": "Sensitive internal information or source code is publicly accessible, potentially exposing credentials or internal logic.",
        "severity": "High",
        "signals": signals
    }
