import dns.resolver
import httpx
import asyncio
from typing import Dict, Any, List, Optional
from app.core.config import settings

# Analysis Lists
CDN_PROVIDERS = [
    "Cloudflare", "Akamai", "Fastly", "CloudFront", "Amazon.com", "EdgeCast", 
    "Limelight", "Incapsula", "Imperva", "Sucuri", "Netlify", "Vercel"
]

CLOUD_PROVIDERS = [
    "Amazon", "Google LLC", "Microsoft Corporation", "DigitalOcean", 
    "Linode", "Vultr", "Oracle", "Alibaba", "Hetzner", "OVH"
]

SHARED_HOSTING_INDICATORS = [
    "GoDaddy", "Bluehost", "HostGator", "Namecheap", "DreamHost", 
    "SiteGround", "InMotion", "Hostinger", "1&1", "Ionos"
]

async def get_ip_data(ip: str) -> Dict[str, Any]:
    """
    Queries public IP intelligence (ISP, ASN, Org) using ip-api.com.
    Note: Rate limit 45/min.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    
    return {"status": "fail"}

def analyze_hosting(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classifies hosting type based on ISP/Org/AS data.
    """
    isp = data.get("isp", "") or ""
    org = data.get("org", "") or ""
    as_info = data.get("as", "") or ""
    
    combined_info = f"{isp} {org} {as_info}".lower()
    
    hosting_type = "Unknown"
    flags = []
    
    # Check CDN
    is_cdn = False
    for provider in CDN_PROVIDERS:
        if provider.lower() in combined_info:
            hosting_type = "CDN / Edge Network"
            is_cdn = True
            flags.append(f"CDN detected: {provider}")
            break
            
    # Check Cloud
    if not is_cdn:
        for provider in CLOUD_PROVIDERS:
            if provider.lower() in combined_info:
                hosting_type = "Cloud Infrastructure"
                flags.append(f"Cloud Provider: {provider}")
                break
                
    # Check Shared
    if hosting_type == "Unknown":
        for provider in SHARED_HOSTING_INDICATORS:
            if provider.lower() in combined_info:
                hosting_type = "Shared/Managed Hosting"
                flags.append("Potential shared infrastructure")
                flags.append("Sensitive data risk on shared host")
                break
                
    if hosting_type == "Unknown" and data.get("hosting") is True:
         hosting_type = "Generic Hosting / Datacenter"

    # Risk Flags
    if not is_cdn:
        flags.append("No CDN / Edge protection detected")

    return {
        "type": hosting_type,
        "flags": flags,
        "provider": org or isp
    }

async def get_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Main entry point. Resolves domain and analyzes IP infrastructure.
    """
    results = {
        "domain": domain,
        "ips": [],
        "hosting_summary": {},
        "flags": []
    }
    
    # 1. Resolve IPs (A/AAAA)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT
    
    resolved_ips = set()
    
    try:
        # A Records
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            resolved_ips.add(rdata.to_text())
    except Exception:
        pass
        
    try:
        # AAAA Records
        answers = resolver.resolve(domain, "AAAA")
        for rdata in answers:
            resolved_ips.add(rdata.to_text())
    except Exception:
        pass
        
    if not resolved_ips:
        return {"error": "Could not resolve domain IPs", "flags": ["Resolution Failed"]}
        
    # 2. Analyze each IP
    ip_details = []
    global_flags = set()
    
    for ip in resolved_ips:
        ip_info = await get_ip_data(ip)
        
        if ip_info.get("status") == "success":
            analysis = analyze_hosting(ip_info)
            
            detail = {
                "ip": ip,
                "asn": ip_info.get("as", "Unknown"),
                "isp": ip_info.get("isp", "Unknown"),
                "location": f"{ip_info.get('city')}, {ip_info.get('countryCode')}",
                "hosting_type": analysis["type"],
                "analysis_flags": analysis["flags"]
            }
            ip_details.append(detail)
            
            # Aggregate flags
            for f in analysis["flags"]:
                global_flags.add(f)
        else:
             ip_details.append({
                 "ip": ip,
                 "error": "Failed to look up ASN/ISP info"
             })

    results["ips"] = ip_details
    results["flags"] = list(global_flags)
    
    return results
