import httpx
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Dict, Any, Optional

# Constants
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" # Generic, non-identifying
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
MAX_REDIRECTS = 3

class SafeHTTPError(Exception):
    pass

def _validate_ip(ip_str: str):
    """
    Raises SafeHTTPError if IP is internal/private/loopback.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise SafeHTTPError(f"Blocked request to internal/private IP: {ip_str}")
        if not ip.is_global:
             raise SafeHTTPError(f"Blocked request to non-global IP: {ip_str}")
    except ValueError:
        raise SafeHTTPError(f"Invalid IP address: {ip_str}")

def _resolve_and_validate(hostname: str) -> str:
    """
    Resolves hostname to IP and validates it against SSRF rules.
    Returns the first valid IP.
    """
    try:
        # standard resolution
        addr_info = socket.getaddrinfo(hostname, None)
        # addr_info is list of (family, type, proto, canonname, sockaddr)
        # sockaddr is (address, port) flow info etc.
        for info in addr_info:
            ip_addr = info[4][0]
            _validate_ip(ip_addr)
            return ip_addr
    except socket.gaierror:
        raise SafeHTTPError(f"Could not resolve hostname: {hostname}")
    except Exception as e:
        if isinstance(e, SafeHTTPError):
            raise
        raise SafeHTTPError(f"Resolution failed: {str(e)}")
    
    raise SafeHTTPError(f"No valid IPs found for resolution of {hostname}")

async def safe_request(method: str, url: str, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Performs a secure HTTP request (GET or HEAD).
    - Validates destination IP (SSRF protection).
    - Enforces size limits.
    - Enforces timeouts.
    - Handles redirects safely (manual check).
    """
    import asyncio
    retries = 3
    base_delay = 1.0
    
    timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)

    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                redirects_left = MAX_REDIRECTS
                current_url = url
                
                while redirects_left >= 0:
                    parsed = urlparse(current_url)
                    if not parsed.hostname:
                        raise SafeHTTPError("Invalid URL: missing hostname")
                    
                    # SSRF Check: Resolve and Validate IP
                    target_ip = _resolve_and_validate(parsed.hostname)
                    
                    # Prepare headers
                    headers = {"User-Agent": USER_AGENT, "Host": parsed.hostname}
                    if extra_headers:
                        headers.update(extra_headers)
                        # Ensure Host matches target hostname for safety
                        headers["Host"] = parsed.hostname
                    
                    # Construct URL using IP
                    if not parsed.scheme:
                        scheme = "http"
                    else:
                        scheme = parsed.scheme
                        
                    # Handle IPv6 brackets
                    formatted_ip = target_ip
                    if ":" in target_ip:
                        formatted_ip = f"[{target_ip}]"
                    
                    request_url = f"{scheme}://{formatted_ip}"
                    if parsed.port:
                        request_url += f":{parsed.port}"
                    if parsed.path:
                        request_url += parsed.path
                    if parsed.query:
                        request_url += f"?{parsed.query}"
    
                    # Perform Request
                    req = client.build_request(method, request_url, headers=headers)
                    
                    response = await client.send(req, stream=True)
                    
                    # Size Limit Check (For GET)
                    content_chunks = []
                    total_size = 0
                    
                    if method == "GET":
                        async for chunk in response.aiter_bytes():
                            total_size += len(chunk)
                            if total_size > MAX_RESPONSE_SIZE:
                                await response.aclose()
                                break
                            content_chunks.append(chunk)
                    else:
                        await response.aclose()
    
                    content = b"".join(content_chunks)
                    content_str = content.decode("utf-8", errors="replace")
    
                    # Handle Redirects
                    if response.is_redirect:
                        next_location = response.headers.get("Location")
                        if not next_location:
                             # Redirect without location? treat as done or break
                             break 
                            
                        if next_location.startswith("/"):
                             next_location = f"{scheme}://{parsed.hostname}{next_location}"
                        elif not next_location.startswith("http"):
                             next_location = f"{scheme}://{parsed.hostname}/{next_location}"
                        
                        current_url = next_location
                        redirects_left -= 1
                        await response.aclose()
                        continue
                    else:
                        return {
                            "status_code": response.status_code,
                            "headers": dict(response.headers),
                            "content_text": content_str,
                            "url": str(response.url)
                        }
    
                raise SafeHTTPError("Max redirects exceeded")

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout, httpx.NetworkError, httpx.RemoteProtocolError) as e:
            if attempt < retries - 1:
                await asyncio.sleep(base_delay * (attempt + 1))
                continue
            raise SafeHTTPError(f"Request failed after {retries} attempts: {str(e)}")
        except Exception as e:
            # Non-retryable
            if isinstance(e, SafeHTTPError):
                raise
            raise SafeHTTPError(str(e))
    
    raise SafeHTTPError("Request failed")

async def safe_get(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return await safe_request("GET", url, headers)

async def safe_head(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return await safe_request("HEAD", url, headers)

