import dns.resolver
from typing import Dict, Any, List, Optional
from app.core.config import settings

# Limit query results to avoid flooding client
MAX_RECORDS_PER_TYPE = 10

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves standard DNS records for a given domain and analyzes email security posture.
    Passive queries only (Standard Resolver).
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    results = {}
    flags = []
    
    resolver = dns.resolver.Resolver()
    # Use public reliable resolvers to avoid local caching issues or limits
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    
    # Enforce Timeouts
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT 
    
    # query_record helper
    def query_record(name: str, rtype: str) -> List[str]:
        try:
            answers = resolver.resolve(name, rtype)
            records = []
            for rdata in answers:
                if rtype == 'TXT':
                    # Robustly handle TXT records which can be split into multiple strings
                    try:
                        text = b''.join(rdata.strings).decode('utf-8')
                    except Exception:
                        text = rdata.to_text().strip('"')
                else:
                    text = rdata.to_text().strip('"')
                    
                records.append(text)
                if len(records) >= MAX_RECORDS_PER_TYPE:
                    break
            return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return []
        except Exception:
            return []

    # 1. Standard Records
    for record_type in record_types:
        results[record_type] = query_record(domain, record_type)

    # 2. Specific Security Records (DMARC)
    # DMARC is always at _dmarc.<domain>
    dmarc_records = query_record(f"_dmarc.{domain}", "TXT")
    
    # 3. DKIM Broad Check
    # We cannot enumerate selectors passively, but we can check if the _domainkey subdomain 
    # has any advertised policies or if specific common selectors exist (avoiding brute force per rules).
    # User requirement: "DKIM presence (record existence only)". 
    # We will just check if a TXT record exists on _domainkey.{domain} which sometimes happens for policy 
    # or if we can find any indication in the root TXT. Use root TXT + _domainkey check.
    domainkey_records = query_record(f"_domainkey.{domain}", "TXT")
    
    # Email Security Analysis
    
    # SPF Analysis
    # SPF is a TXT record on the root domain starting with "v=spf1"
    root_txt = results.get("TXT", [])
    spf_record = next((r for r in root_txt if "v=spf1" in r), None)
    
    spf_data = {
        "present": bool(spf_record),
        "record": spf_record,
        "status": "Missing"
    }

    if spf_record:
        if "+all" in spf_record:
            spf_data["status"] = "Over-permissive (+all)"
            flags.append("Over-permissive SPF policy (+all)")
        elif "-all" in spf_record:
            spf_data["status"] = "Strict (-all)"
        elif "~all" in spf_record:
            spf_data["status"] = "SoftFail (~all)"
        elif "?all" in spf_record:
            spf_data["status"] = "Neutral (?all)"
        else:
            spf_data["status"] = "Unknown/Loose"
            
    # DMARC Analysis
    dmarc_record = next((r for r in dmarc_records if "v=DMARC1" in r), None)
    dmarc_policy = "None"
    
    if dmarc_record:
        # Simple parse for p=
        parts = dmarc_record.split(";")
        for part in parts:
            if part.strip().startswith("p="):
                dmarc_policy = part.split("=")[1].strip()
                break
    else:
        flags.append("Missing DMARC record")

    dmarc_data = {
        "present": bool(dmarc_record),
        "record": dmarc_record,
        "policy": dmarc_policy
    }

    # DKIM Presence
    # If we found anything at _domainkey.{domain} or if standard selectors were somehow visible (not implementing brute force).
    # Just reporting if we found any TXT record at _domainkey as a hint of configuration.
    dkim_present = len(domainkey_records) > 0
    # Note: This is weak evidence, but compliant with "passive" and "no iteration".
    
    results["email_security"] = {
        "spf": spf_data,
        "dmarc": dmarc_data,
        "dkim_dns_check": {
            "_domainkey_exists": dkim_present,
            "note": "Selectors not enumerated passively"
        }
    }
    
    results["flags"] = flags

    return results
