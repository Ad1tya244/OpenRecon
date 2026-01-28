import asyncio
import dns.resolver
from typing import Dict, Any, List, Set
from app.modules import subdomain_recon, ip_hosting_asn_intelligence
from app.core.config import settings

async def map_network_footprint(domain: str) -> Dict[str, Any]:
    """
    Maps the network footprint by correlating subdomains, IPs, and ASNs.
    """
    network_map = {
        "domain": domain,
        "summary": {
            "total_subdomains": 0,
            "unique_ips": 0,
            "unique_asns": 0,
            "locations": [],
            "hosting_providers": []
        },
        "network_graph": {
            "subnets": {},
            "asns": {},
            "cdns": []
        },
        "exposure_analysis": {
             "cloud_ips": 0,
             "hosting_ips": 0,
             "unprotected_ips": 0
        }
    }
    
    # 1. Get Subdomains
    # We re-run enumeration or assume user calls this after? 
    # Let's run it.
    sub_results = await subdomain_recon.enumerate_subdomains(domain)
    subdomains = [s["hostname"] for s in sub_results.get("subdomains", [])]
    network_map["summary"]["total_subdomains"] = len(subdomains)
    
    # Include the root domain
    base_domain_targets = [domain] + subdomains
    
    # 2. Resolve IPs (Bulk/Parallel)
    # We need to map Hostname -> IP -> ASN
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    ip_to_hostnames = {}
    unique_ips = set()
    
    # Limit resolution to avoid massive DNS time for huge scopes (e.g. first 50 subdomains)
    # For a demo tool, 50 is reasonable.
    targets_to_resolve = base_domain_targets[:50] 
    
    for hostname in targets_to_resolve:
        try:
            # Try A records
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                ip = rdata.to_text()
                unique_ips.add(ip)
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                ip_to_hostnames[ip].append(hostname)
        except Exception:
            pass
            
    network_map["summary"]["unique_ips"] = len(unique_ips)
    
    # 3. Enrich IPs (ASN/Hosting)
    # Use ip_hosting_asn_intelligence logic
    
    # Rate Limit Safeguard: Limit enrichment to top 20 unique IPs to avoid ip-api ban (45/min)
    ips_to_enrich = list(unique_ips)[:20]
    
    asn_map = {}
    
    def normalize_provider(name: str) -> str:
        name = name.replace(", Inc.", "").replace(", LLC", "").replace(" Inc.", "").replace(" LLC", "")
        name = name.replace("Private Limited", "").strip()
        if "Amazon" in name or "AWS" in name:
            return "Amazon AWS"
        if "Google" in name:
            return "Google Cloud"
        if "DigitalOcean" in name or "Digital Ocean" in name:
            return "DigitalOcean"
        if "Cloudflare" in name:
            return "Cloudflare"
        if "Microsoft" in name:
            return "Microsoft Azure"
        return name

    for ip in ips_to_enrich:
        # 1-second delay could be added if needed, but if <20, should be fine
        ip_data = await ip_hosting_asn_intelligence.get_ip_data(ip)
        
        if ip_data.get("status") == "success":
            analysis = ip_hosting_asn_intelligence.analyze_hosting(ip_data)
            
            asn = ip_data.get("as", "Unknown ASN")
            isp = ip_data.get("isp", "Unknown ISP")
            loc = f"{ip_data.get('city', '')}, {ip_data.get('countryCode', '')}"
            country = ip_data.get("country", "")
            
            # Populate ASN Map
            if asn not in network_map["network_graph"]["asns"]:
                network_map["network_graph"]["asns"][asn] = {
                    "description": isp,
                    "ips": [],
                    "country": country
                }
            network_map["network_graph"]["asns"][asn]["ips"].append(ip)
            
            # Locations
            if loc not in network_map["summary"]["locations"]:
                network_map["summary"]["locations"].append(loc)
                
            # Hosting (Normalized)
            provider_raw = analysis.get("provider", isp)
            provider_norm = normalize_provider(provider_raw)
            if provider_norm and provider_norm not in network_map["summary"]["hosting_providers"]:
                network_map["summary"]["hosting_providers"].append(provider_norm)
                
            # Exposure Stats
            h_type = analysis.get("type", "Unknown")
            if "Cloud" in h_type:
                network_map["exposure_analysis"]["cloud_ips"] += 1
            elif "Shared" in h_type:
                network_map["exposure_analysis"]["hosting_ips"] += 1
                
            # Check for Unprotected IPs
            if "No CDN" in analysis.get("flags", []) or "No CDN" in str(analysis.get("flags")):
                 # Simplified check
                 is_cdn = False
                 for f in analysis.get("flags", []):
                     if "CDN" in f and "No CDN" not in f:
                         is_cdn = True
                 if not is_cdn:
                     network_map["exposure_analysis"]["unprotected_ips"] += 1
                     if "unprotected_ips_list" not in network_map["exposure_analysis"]:
                         network_map["exposure_analysis"]["unprotected_ips_list"] = []
                     network_map["exposure_analysis"]["unprotected_ips_list"].append(ip)
            
            # CDN Graph
            for f in analysis.get("flags", []):
                if "CDN detected" in f:
                    cdn_name = f.split(": ")[-1]
                    if cdn_name not in network_map["network_graph"]["cdns"]:
                        network_map["network_graph"]["cdns"].append(cdn_name)

    network_map["summary"]["unique_asns"] = len(network_map["network_graph"]["asns"])
    
    return network_map
