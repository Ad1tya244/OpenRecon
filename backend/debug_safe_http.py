import asyncio
import httpx
import socket
from urllib.parse import urlparse

async def test():
    target = "bmsit.ac.in"
    url = f"https://{target}"
    
    print(f"Testing {url}...")
    
    # 1. Normal Request (Control)
    print("\n--- Control (Normal Request) ---")
    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.get(url)
            print(f"Status: {resp.status_code}")
            print(f"Server: {resp.headers.get('server')}")
            print(f"Redir: {resp.history}")
    except Exception as e:
        print(f"Control Failed: {e}")

    # 2. Safe Request Logic (Simulation)
    print("\n--- Safe Logic (IP Substitution) ---")
    try:
        # Resolve
        addr_info = socket.getaddrinfo(target, None)
        target_ip = addr_info[0][4][0]
        print(f"Resolved to: {target_ip}")
        
        # Construct IP URL
        ip_url = f"https://{target_ip}"
        headers = {"Host": target, "User-Agent": "Mozilla/5.0"}
        
        async with httpx.AsyncClient(verify=False) as client:
            # Note: This sends SNI=<IP>
            resp = await client.get(ip_url, headers=headers)
            print(f"Status: {resp.status_code}")
            print(f"Server: {resp.headers.get('server')}")
            if resp.status_code == 404 or resp.status_code == 403:
                print("Likely failed due to SNI mismatch/Host header check")
    except Exception as e:
        print(f"Safe Logic Failed: {e}")

asyncio.run(test())
