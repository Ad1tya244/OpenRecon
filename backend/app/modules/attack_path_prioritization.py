from typing import Dict, Any, List

def analyze_attack_paths(scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyzes OSINT findings to simulate and prioritize potential attacker decision paths.
    
    WARNING: READ-ONLY ANALYSIS.
    This module simulates decision making based on public exposure.
    It does NOT perform any active scanning or exploitation.
    """
    attack_paths = []
    
    # Extract Modules
    subdomains = scan_data.get("subdomains", [])
    if isinstance(subdomains, dict): subdomains = subdomains.get("subdomains", [])
    
    ports = scan_data.get("ports", {})
    open_ports = ports.get("open_ports", []) if isinstance(ports, dict) else []
    
    tech = scan_data.get("tech", {})
    code_leaks = scan_data.get("code_leaks", {})
    public_files = scan_data.get("public_files", {})
    
    # -----------------------------------------------------
    # Path 1: Exposed Secrets / Configuration
    # -----------------------------------------------------
    # Logic: Found .env, config, or API keys in public files/code leaks
    leaked_items = []
    
    # Check Public Files
    found_files = public_files.get("found", []) if isinstance(public_files, dict) else []
    critical_files = [f for f in found_files if any(x in str(f).lower() for x in ['.env', 'config', 'secret', 'key'])]
    if critical_files:
        leaked_items.extend(critical_files)
        
    # Check Code Leaks
    leak_findings = code_leaks.get("findings", []) if isinstance(code_leaks, dict) else []
    if leak_findings:
        leaked_items.extend([f"{l.get('repository')} ({l.get('type')})" for l in leak_findings])

    if leaked_items:
        attack_paths.append({
            "title": "Credential / Secret Harvesting",
            "sequence": [
                "Identify exposed configuration files or code repositories.",
                "Extract hardcoded API keys, database credentials, or internal URLs.",
                "Use credentials to authenticate against cloud services or internal panels."
            ],
            "entry_point": f"Exposed Assets: {', '.join(leaked_items[:3])}",
            "effort": "Low",
            "stealth": "Stealthy (Passive)",
            "evidence": f"Found {len(leaked_items)} exposed secrets/config files.",
            "disclaimer": "Simulated attack path based on OSINT inference."
        })

    # -----------------------------------------------------
    # Path 2: Administrative Interface Access
    # -----------------------------------------------------
    # Logic: Admin subdomain + Login page + Known CMS/Framework
    admin_keywords = ["admin", "login", "portal", "dashboard", "vpn", "manager"]
    exposed_admin_subs = []
    
    if isinstance(subdomains, list):
        for s in subdomains:
            s_name = s.get("hostname", "") if isinstance(s, dict) else str(s)
            if any(k in s_name.lower() for k in admin_keywords):
                exposed_admin_subs.append(s_name)
    
    if exposed_admin_subs:
        path = {
            "title": "Administrative Interface Guessing",
            "sequence": [
                "Target exposed administrative subdomains.",
                "Identify login portal technology (e.g., WordPress, Okta, Custom).",
                "Attempt credential stuffing or default credential login."
            ],
            "entry_point": f"Subdomains: {', '.join(exposed_admin_subs[:3])}",
            "effort": "Medium",
            "stealth": "Noisy (Active Auth)",
            "evidence": f"Found {len(exposed_admin_subs)} admin-related subdomains.",
            "disclaimer": "Simulated attack path based on OSINT inference."
        }
        
        # Tech convergence makes it higher impact
        frameworks = tech.get("frameworks", [])
        if frameworks:
             path["sequence"].insert(1, f"Leverage known stack info ({', '.join(frameworks)}) for specific default coords.")
             
        attack_paths.append(path)

    # -----------------------------------------------------
    # Path 3: Unprotected Development/Staging Environment
    # -----------------------------------------------------
    dev_keywords = ["dev", "stage", "test", "uat", "beta", "demo"]
    dev_subs = []
    if isinstance(subdomains, list):
        for s in subdomains:
            s_name = s.get("hostname", "") if isinstance(s, dict) else str(s)
            if any(k in s_name.lower() for k in dev_keywords):
                dev_subs.append(s_name)
                
    if dev_subs:
        attack_paths.append({
            "title": "Staging Environment Exploitation",
            "sequence": [
                "Target non-production environments (dev/stage).",
                "Exploit likely weaker security controls (debug mode, default passwords).",
                "Pivot from staging to production via shared secrets or database connections."
            ],
            "entry_point": f"Subdomains: {', '.join(dev_subs[:3])}",
            "effort": "Low",
            "stealth": "Stealthy (Often unmonitored)",
            "evidence": f"Found {len(dev_subs)} non-production environments.",
            "disclaimer": "Simulated attack path based on OSINT inference."
        })

    # -----------------------------------------------------
    # Path 4: Known Vulnerable Service Exploitation
    # -----------------------------------------------------
    # Logic: Old server version or specific vulnerable port (e.g., 21 FTP, 23 Telnet, 445 SMB)
    risky_ports = {
        21: "FTP",
        23: "Telnet", 
        445: "SMB",
        3389: "RDP",
        5900: "VNC"
    }
    
    found_risky = []
    for p in open_ports:
        port_num = int(p.get("port", 0))
        if port_num in risky_ports:
            found_risky.append(f"{port_num} ({risky_ports[port_num]})")
            
    if found_risky:
        attack_paths.append({
            "title": "Legacy Service Exploitation",
            "sequence": [
                "Target legacy services exposed on public interfaces.",
                "Attempt protocol-specific exploits or brute force.",
                "Gain initial shell or system access."
            ],
            "entry_point": f"Ports: {', '.join(found_risky)}",
            "effort": "Medium",
            "stealth": "Noisy (Exploit attempts)",
            "evidence": "Detected exposure of high-risk legacy management services.",
            "disclaimer": "Simulated attack path based on OSINT inference."
        })

    # -----------------------------------------------------
    # Path 5: Cloud Asset Misconfiguration
    # -----------------------------------------------------
    # Logic: Cloud IPs found without protection or S3 buckets (hints in public files)
    net = scan_data.get("network_footprint", {})
    exposure = net.get("exposure_analysis", {}) if isinstance(net, dict) else {}
    unprotected = exposure.get("unprotected_ips", 0)
    
    if unprotected > 0:
        attack_paths.append({
            "title": "Cloud Infrastructure Bypass",
            "sequence": [
                "Target direct IP addresses bypassing WAF/CDN.",
                "Access application origins directly to evade IP restrictions.",
                "Scan for cloud metadata services (SSRF)."
            ],
            "entry_point": f"{unprotected} Unprotected Cloud IPs Identified",
            "effort": "Medium",
            "stealth": "Stealthy (Direct IP access)",
            "evidence": "Found cloud origins exposed directly to the internet.",
            "disclaimer": "Simulated attack path based on OSINT inference."
        })

    # Sort Priority: Low Effort + Stealthy > Low Effort + Noisy > Medium Effort
    # Simple heuristic scoring
    def score_path(p):
        score = 0
        if p["effort"] == "Low": score += 3
        elif p["effort"] == "Medium": score += 2
        
        if "Stealthy" in p["stealth"]: score += 2
        
        # Secret harvesting is usually top priority
        if "Secret" in p["title"]: score += 5
        
        return score

    attack_paths.sort(key=score_path, reverse=True)
    
    return attack_paths
