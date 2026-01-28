import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from app.modules.tech_fingerprint import get_tech_fingerprint
from app.modules.headers_recon import analyze_headers

async def test():
    domain = "bmsit.ac.in"
    print(f"Testing modules for: {domain}")
    
    print("\n--- Tech Fingerprint ---")
    try:
        tech = await get_tech_fingerprint(domain)
        print(tech)
    except Exception as e:
        print(f"Tech failed: {e}")

    print("\n--- Headers Recon ---")
    try:
        headers = await analyze_headers(domain)
        print(headers)
    except Exception as e:
        print(f"Headers failed: {e}")

if __name__ == "__main__":
    asyncio.run(test())
