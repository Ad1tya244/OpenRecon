from typing import Dict, Any, List

def correlate_intelligence(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Correlates raw signals from various modules to generate high-level intelligence findings.
    
    Output Format:
    [
        {
            "title": "Exposed Admin Surface",
            "description": "...",
            "severity": "High",
            "signals": ["Subdomain: admin.example.com", "Tech: PHP"]
        }
    ]
    """
    findings = []
    
    # helper to safely get lists/dicts
    def get_list(data: Any) -> List:
        return data if isinstance(data, list) else []

    # 1. Exposed Admin Surface
    # Correlation: Subdomains containing 'admin', 'vpn', 'dashboard', 'portal' 
    #              AND sensitive ports (SSH, RDP) or weak auth hints.
    adming_findings = _check_admin_exposure(scan_data)
    if adming_findings:
        findings.append(adming_findings)
        
    # 2. Weak Email Security Posture
    # Correlation: DNS (SPF/DMARC) + Whois (is org legitimate?)
    email_findings = _check_email_security(scan_data)
    if email_findings:
        findings.append(email_findings)
        
    # 3. Legacy Application Exposure
    # Correlation: Tech (old versions), Headers (Powered-By old versions), SSL (TLS 1.0/1.1)
    legacy_findings = _check_legacy_exposure(scan_data)
    if legacy_findings:
        findings.append(legacy_findings)
        
    # 4. Data Leak / Public Exposure Risks
    # Correlation: Public Files + Code Leaks + Directory Exposure
    leak_findings = _check_leak_risks(scan_data)
    if leak_findings:
        findings.append(leak_findings)

    return findings

def _check_admin_exposure(data: Dict[str, Any]) -> Dict[str, Any]:
    subdomains = data.get("subdomains", [])
    if isinstance(subdomains, dict): 
        subdomains = subdomains.get("subdomains", []) # Handle different API structures
        
    # Normalize subdomain list
    subs_list = []
    if isinstance(subdomains, list):
        for s in subdomains:
            if isinstance(s, dict): subs_list.append(s.get("hostname", ""))
            elif isinstance(s, str): subs_list.append(s)

    admin_keywords = ["admin", "vpn", "dashboard", "portal", "internal", "dev", "staging", "test"]
    exposed_subs = [s for s in subs_list if any(k in s.lower() for k in admin_keywords)]
    
    ports_data = data.get("ports", {})
    open_ports = ports_data.get("open_ports", []) if isinstance(ports_data, dict) else []
    admin_ports = [p for p in open_ports if p.get("port") in [22, 3389, 9090, 8443, 10000]]
    
    signals = []
    if exposed_subs:
        signals.append(f"Exposed administrative subdomains: {', '.join(exposed_subs[:5])}" + ("..." if len(exposed_subs)>5 else ""))
    if admin_ports:
        signals.append(f"Administrative ports open: {', '.join([str(p.get('port')) for p in admin_ports])}")
        
    if signals:
        severity = "High" if admin_ports else "Medium"
        return {
            "title": "Exposed Administrative Surface",
            "description": "Administrative interfaces or internal portals are exposed to the public internet. This increases the attack surface for brute-force or exploitation attacks.",
            "severity": severity,
            "signals": signals
        }
    return None

def _check_email_security(data: Dict[str, Any]) -> Dict[str, Any]:
    dns = data.get("dns", {})
    if not isinstance(dns, dict): return None
    
    email_sec = dns.get("email_security", {})
    spf = email_sec.get("spf", {})
    dmarc = email_sec.get("dmarc", {})
    
    signals = []
    severity = "Low"
    
    # SPF Logic
    if not spf.get("present"):
        signals.append("Missing SPF record")
        severity = "Medium"
    elif spf.get("status") == "softfail" or "~all" in spf.get("record", ""):
        signals.append("Weak SPF Policy (~all)")
        
    # DMARC Logic
    if not dmarc.get("present"):
        signals.append("Missing DMARC record")
        severity = "Medium"
    elif dmarc.get("policy") == "none":
         signals.append("DMARC Policy is 'none' (Monitoring only)")
         
    if signals:
        if "Missing SPF record" in signals and "Missing DMARC record" in signals:
            severity = "High"
            
        return {
            "title": "Weak Email Security Posture",
            "description": "Domain lacks properly enforced email authentication controls (SPF/DMARC), making it susceptible to spoofing and phishing abuse.",
            "severity": severity,
            "signals": signals
        }
    return None

def _check_legacy_exposure(data: Dict[str, Any]) -> Dict[str, Any]:
    tech = data.get("tech", {})
    if not isinstance(tech, dict): return None
    
    signals = []
    
    # PHP Version Check (Heuristic)
    # Ideally we'd parse versions, but for now we look for 'PHP' in general if headers say 'X-Powered-By: PHP/5.x'
    # Since we heavily rely on Wappalyzer/Simple logic, we might just look at the list
    
    server = tech.get("server", "")
    if server and ("apache/2.2" in server.lower() or "nginx/1.10" in server.lower() or "iis/7" in server.lower()):
        signals.append(f"Legacy Web Server Detected: {server}")
        
    frameworks = tech.get("frameworks", [])
    for f in frameworks:
        if "jquery" in f.lower() or "bootstrap" in f.lower():
             # Very generic, but usually implies older stack if dominant
             pass
             
    # SSL Check
    ssl_data = data.get("ssl", {})
    if isinstance(ssl_data, dict):
        # If we had protocols, we'd check for TLS 1.0. 
        # Assuming 'is_valid' is false might imply some legacy issues too.
        if ssl_data.get("is_expired"):
             signals.append("SSL Certificate Expired")

    if signals:
        return {
            "title": "Legacy Application Exposure",
            "description": "Evidence of outdated web servers or components which may harbor known vulnerabilities.",
            "severity": "Medium",
            "signals": signals
        }
    return None

def _check_leak_risks(data: Dict[str, Any]) -> Dict[str, Any]:
    signals = []
    severity = "Medium"
    
    # Code Leaks
    leaks = data.get("code_leaks", {})
    if isinstance(leaks, dict) and leaks.get("count", 0) > 0:
        signals.append(f"Found {leaks.get('count')} potential code leaks on public repositories")
        severity = "High"
        
    # Public Files
    pub_files = data.get("public_files", {})
    if isinstance(pub_files, dict):
        findings = pub_files.get("interesting_findings", [])
        if findings:
            signals.extend(findings)
            
    # Directory Exposure
    dir_exp = data.get("directory_exposure", {})
    if isinstance(dir_exp, dict):
        exposed = dir_exp.get("exposed_directories", [])
        if exposed:
             signals.append(f"Open Directory Listings found: {len(exposed)} paths")
             severity = "High"

    if signals:
        return {
             "title": "Data Leak & Public Exposure Risk",
             "description": "Sensitive information or internal structures are publicly accessible.",
             "severity": severity,
             "signals": signals
        }
    return None
