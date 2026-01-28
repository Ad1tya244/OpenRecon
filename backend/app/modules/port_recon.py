import asyncio
import socket
from typing import Dict, Any, List
from app.core.config import settings

# Safe Top Ports
TOP_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    3306: "MySQL",
    3389: "RDP"
}

async def check_port(domain: str, port: int) -> bool:
    """
    Checks if a single port is open using asyncio.open_connection.
    Timeout is strict (1-2s) to avoid hanging.
    """
    try:
        # We use wait_for to enforce strict timeout per port
        future = asyncio.open_connection(domain, port)
        reader, writer = await asyncio.wait_for(future, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:
        return False

async def scan_ports(domain: str) -> Dict[str, Any]:
    """
    Scans top ports concurrently.
    """
    results = {
        "open_ports": [],
        "scanned_ports": list(TOP_PORTS.keys())
    }
    
    tasks = []
    for port, service in TOP_PORTS.items():
        tasks.append((port, service, check_port(domain, port)))
        
    # Run all port checks concurrently
    for port, service, coro in tasks:
        is_open = await coro
        if is_open:
            results["open_ports"].append({
                "port": port,
                "service": service
            })
            
    return results
