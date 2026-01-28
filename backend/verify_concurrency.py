import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from app.modules.tech_fingerprint import get_tech_fingerprint
from app.modules.headers_recon import analyze_headers

async def test_concurrency():
    domain = "bmsit.ac.in"
    print(f"Testing concurrency for: {domain}")
    
    tasks = []
    # Simulate 5 concurrent requests (like the dashboard)
    # Tech and Headers run in parallel in dashboard + others
    for i in range(3):
        tasks.append(get_tech_fingerprint(domain))
        tasks.append(analyze_headers(domain))
        
    print(f"Firing {len(tasks)} requests...")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, res in enumerate(results):
        status = "OK"
        if isinstance(res, dict) and "error" in res:
            status = f"ERROR: {res['error']}"
        elif isinstance(res, Exception):
            status = f"EXCEPTION: {res}"
        print(f"Req {i}: {status}")

if __name__ == "__main__":
    asyncio.run(test_concurrency())
