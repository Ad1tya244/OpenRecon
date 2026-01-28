import socket
import re
from typing import Dict, Any, Optional
from datetime import datetime
from app.core.config import settings

def get_whois_server(domain: str) -> str:
    """
    Simple heuristic to find whois server.
    """
    tld = domain.split('.')[-1]
    # Specialized servers for common TLDs to ensure better data
    servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'uk': 'whois.nic.uk',
        'jp': 'whois.jprs.jp',
        'in': 'whois.nixiregistry.in',
        'ac.in': 'whois.nixiregistry.in'
    }
    # Heuristic for 2nd level TLDs like co.uk, ac.in
    if domain.endswith('.ac.in') or domain.endswith('.co.in') or domain.endswith('.net.in') or domain.endswith('.org.in'):
         return 'whois.nixiregistry.in'

    return servers.get(tld, f"whois.nic.{tld}")

def parse_date(date_str: str) -> Optional[datetime]:
    """
    Attempts to parse WHOIS date strings in various formats.
    """
    if not date_str:
        return None
        
    # Clean string
    date_str = date_str.strip()
    
    # Common formats
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",       # ISO 8601
        "%Y-%m-%dT%H:%M:%S.%fZ",    # ISO with millis
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",                 # Simple date
        "%d-%b-%Y",                 # 01-Jan-2020
        "%Y.%m.%d",                 # 2020.01.01
        "%a %b %d %H:%M:%S %Z %Y",  # Sat Jan 01 00:00:00 GMT 2020 (Unix style)
        "%d/%m/%Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
            
    # If all fail, try slicing T if it exists (for variations like T12:00:00+0000)
    if "T" in date_str:
        try:
            # Try just the date part
            return datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        except ValueError:
            pass
            
    return None

def parse_whois_data(raw_text: str) -> Dict[str, Any]:
    """
    Parses raw WHOIS text for key information using regex.
    Handles variable formats.
    """
    data = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "scan_date": datetime.now().isoformat(),
        "flags": [],
        "raw_preview": raw_text[:500] + "..." if raw_text else ""
    }
    
    # Regex patterns for common fields
    patterns = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
            r"registrar:\s*(.+)",
            r"Organization:\s*(.+)"
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"Registered on:\s*(.+)",
            r"created:\s*(.+)",
            r"Created On:\s*(.+)",
            r"Creation Date\s*:\s*(.+)"
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"Expiry date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Expires On:\s*(.+)",
            r"Expiration Date\s*:\s*(.+)"
        ]
    }
    
    for key, regex_list in patterns.items():
        for pattern in regex_list:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                # Basic cleaning
                data[key] = value
                break
                
    # Calculate Age
    if data["creation_date"]:
        created_dt = parse_date(data["creation_date"])
        if created_dt:
            data["creation_date_iso"] = created_dt.isoformat()
            now = datetime.now()
            age = (now - created_dt).days
            data["age_days"] = age
            
            # Risk Flag
            if age < 90: # 3 months or less
                data["flags"].append("Recently registered (New Domain)")
        else:
            data["creation_date_parsed"] = "Failed to parse"

    return data

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves and parses WHOIS info using raw sockets (No subprocess).
    Safely handles connection errors and timeouts.
    """
    server = get_whois_server(domain)
    
    try:
        # 1. Connect to Whois Server
        with socket.create_connection((server, 43), timeout=settings.SOCKET_TIMEOUT) as sock:
            # 2. Send Query
            sock.sendall(f"{domain}\r\n".encode())
            
            # 3. Read Response
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data.decode(errors='replace'))
            
            response = "".join(chunks)

            # 4. Parse Response
            parsed_data = parse_whois_data(response)
            
            return parsed_data

    except socket.timeout:
         return {
            "error": "Whois connection timed out",
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "flags": ["Whois Timeout"]
        }
    except Exception as e:
        # Fail closed/safe
        return {
            "error": "Whois lookup failed",
            "details": str(e), 
            "registrar": "Unknown",
            "creation_date": "Unknown"
        }
