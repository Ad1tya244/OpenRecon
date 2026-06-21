import warnings
# Suppress 'asyncio.iscoroutinefunction is deprecated' from slowapi/starlette internals.
# These are upstream bugs — the warning fires from site-packages, not our code.
# Safe to suppress: the function still works until Python 3.16.
warnings.filterwarnings(
    "ignore",
    message=".*asyncio\\.iscoroutinefunction.*",
    category=DeprecationWarning,
)

from app.utils.dotenv import load_dotenv
load_dotenv()

from datetime import datetime

from fastapi import FastAPI, Request
from app.modules import dns_recon, whois_recon, ssl_recon, headers_recon, subdomain_recon, tech_fingerprint, security_headers_recon, public_files_recon, directory_exposure_recon, code_leak_recon, historical_recon, attack_surface_mapper, report_generator, port_recon, ip_hosting_asn_intelligence, network_footprint_mapper, unified_attack_surface_graph, attack_surface_intelligence
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


# Initialize Rate Limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="OpenRecon API",
    description="Passive OSINT Reconnaissance API",
    version="1.0.0",
    docs_url=None, # Disable Swagger UI for production/security
    redoc_url=None
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global Exception Handler (Hides Stack Traces)
from app.utils.error_handler import centralized_exception_handler

# Global Exception Handler (Hides Stack Traces)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return await centralized_exception_handler(request, exc)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@limiter.limit("5/minute")
async def root(request: Request):
    return {"message": "OpenRecon API is running. use /scan/{module}?domain=example.com"}

@app.get("/health")
async def health_check():
    return {"status": "ok"}

from fastapi import HTTPException
from app.utils.input_validator import validate_target

def get_validated_target(target: str) -> str:
    result = validate_target(target)
    if not result.is_valid:
        raise HTTPException(status_code=400, detail=result.error_message)
    return result.normalized_input



@app.get("/dns")
@limiter.limit("5/minute")
async def scan_dns(request: Request, domain: str):
    domain = get_validated_target(domain)
    return dns_recon.get_dns_records(domain)

@app.get("/whois")
@limiter.limit("5/minute")
async def scan_whois(request: Request, domain: str):
    domain = get_validated_target(domain)
    return whois_recon.get_whois_info(domain)

@app.get("/ssl")
@limiter.limit("5/minute")
async def scan_ssl(request: Request, domain: str):
    domain = get_validated_target(domain)
    return ssl_recon.analyze_ssl(domain)

@app.get("/headers")
@limiter.limit("5/minute")
async def scan_headers(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await headers_recon.analyze_headers(domain)

@app.get("/subdomains")
@limiter.limit("5/minute")
async def scan_subdomains(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await subdomain_recon.enumerate_subdomains(domain)

@app.get("/tech")
@limiter.limit("5/minute")
async def scan_tech(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await tech_fingerprint.get_tech_fingerprint(domain)

@app.get("/security-headers")
@limiter.limit("5/minute")
async def scan_security_headers(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await security_headers_recon.analyze_security_headers(domain)

@app.get("/public-files")
@limiter.limit("5/minute")
async def scan_public_files(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await public_files_recon.check_public_files(domain)

@app.get("/directory-exposure")
@limiter.limit("5/minute")
async def scan_directory_exposure(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await directory_exposure_recon.check_directory_exposure(domain)

@app.get("/code-leaks")
@limiter.limit("5/minute")
async def scan_code_leaks(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await code_leak_recon.check_code_leaks(domain)

@app.get("/historical")
@limiter.limit("5/minute")
async def scan_historical(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await historical_recon.check_historical_data(domain)

@app.get("/ip-intelligence")
@limiter.limit("5/minute")
async def scan_ip_intelligence(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await ip_hosting_asn_intelligence.get_domain_intelligence(domain)

@app.get("/network-footprint")
@limiter.limit("5/minute")
async def scan_network_footprint(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await network_footprint_mapper.map_network_footprint(domain)

@app.get("/graph")
@limiter.limit("3/minute")
async def scan_graph(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await unified_attack_surface_graph.build_graph(domain)

import asyncio
import inspect
import logging
from functools import partial

logger = logging.getLogger("OpenRecon")

async def run_module_safely(module_name: str, func, *args):
    """
    Executes a module function safely with a timeout.
    - Async functions: awaited directly with asyncio.wait_for
    - Sync functions: run in a thread pool via run_in_executor so they
      don't block the event loop.
    Returns the result or an error dict — never raises.
    """
    timeout = 45  # seconds per module
    loop = asyncio.get_running_loop()
    try:
        if inspect.iscoroutinefunction(func):
            return await asyncio.wait_for(func(*args), timeout=timeout)
        else:
            # Run blocking/sync functions off the event loop thread
            return await asyncio.wait_for(
                loop.run_in_executor(None, partial(func, *args)),
                timeout=timeout
            )
    except asyncio.TimeoutError:
        logger.error(f"Module {module_name} timed out")
        return {"error": "Module timed out"}
    except Exception as e:
        logger.error(f"Module {module_name} failed: {str(e)}")
        return {"error": f"Module execution failed: {type(e).__name__}"}

# In-memory intelligence cache: {domain: (timestamp, result)}
# Avoids re-running _orchestrate_full_scan when /scan/intelligence is called
# right after the dashboard has already fetched all individual modules.
_intel_cache: dict = {}
INTEL_CACHE_TTL = 300   # 5 minutes
INTEL_CACHE_MAX = 10    # max domains kept

async def _orchestrate_full_scan(domain: str):
    """
    Runs all 14 recon modules concurrently via asyncio.gather.
    Previously sequential — this cuts wall-clock time from sum(timeouts) to max(timeout).
    """
    (
        dns_res, whois_res, ssl_res, headers_res, tech_res,
        sec_headers_res, subdomains_res, public_files_res, dir_exp_res,
        code_leaks_res, historical_res, ports_res, ip_res, net_res
    ) = await asyncio.gather(
        run_module_safely("DNS",                dns_recon.get_dns_records,                          domain),
        run_module_safely("Whois",              whois_recon.get_whois_info,                         domain),
        run_module_safely("SSL",                ssl_recon.analyze_ssl,                              domain),
        run_module_safely("Headers",            headers_recon.analyze_headers,                      domain),
        run_module_safely("Tech",               tech_fingerprint.get_tech_fingerprint,              domain),
        run_module_safely("Security Headers",   security_headers_recon.analyze_security_headers,    domain),
        run_module_safely("Subdomains",         subdomain_recon.enumerate_subdomains,               domain),
        run_module_safely("Public Files",       public_files_recon.check_public_files,              domain),
        run_module_safely("Directory Exposure", directory_exposure_recon.check_directory_exposure,  domain),
        run_module_safely("Code Leaks",         code_leak_recon.check_code_leaks,                  domain),
        run_module_safely("Historical",         historical_recon.check_historical_data,             domain),
        run_module_safely("Ports",              port_recon.scan_ports,                              domain),
        run_module_safely("IP Intelligence",    ip_hosting_asn_intelligence.get_domain_intelligence,domain),
        run_module_safely("Network Footprint",  network_footprint_mapper.map_network_footprint,     domain),
    )

    full_data = {
        "target": domain,
        "dns": dns_res, "whois": whois_res, "ssl": ssl_res,
        "headers": headers_res, "tech": tech_res,
        "security_headers": sec_headers_res, "subdomains": subdomains_res,
        "public_files": public_files_res, "directory_exposure": dir_exp_res,
        "code_leaks": code_leaks_res, "historical": historical_res,
        "ports": ports_res, "ip_intelligence": ip_res, "network_footprint": net_res
    }

    try:
        full_data["attack_surface"] = attack_surface_mapper.map_attack_surface(full_data)
    except Exception as e:
        full_data["attack_surface"] = {"error": f"Mapping failed: {str(e)}", "risk_assessment": {"score": 0, "grade": "F"}}

    return full_data

@app.get("/full")
@limiter.limit("2/minute")
async def scan_full(request: Request, domain: str):
    domain = get_validated_target(domain)
    full_data = await _orchestrate_full_scan(domain)
    return {
        "target": domain,
        "attack_surface": full_data.get("attack_surface"),
        "full_results": full_data
    }

@app.get("/ports")
@limiter.limit("2/minute")
async def scan_ports(request: Request, domain: str):
    domain = get_validated_target(domain)
    return await port_recon.scan_ports(domain)

@app.get("/intelligence")
@limiter.limit("10/minute")
async def scan_intelligence(request: Request, domain: str):
    import time
    domain = get_validated_target(domain)

    # Serve from cache if fresh
    now = time.monotonic()
    if domain in _intel_cache:
        ts, cached = _intel_cache[domain]
        if now - ts < INTEL_CACHE_TTL:
            logger.info(f"Intelligence cache hit for {domain}")
            return cached

    full_data = await _orchestrate_full_scan(domain)
    result = attack_surface_intelligence.generate_intelligence(full_data)

    # Store in cache, evict oldest if over limit
    _intel_cache[domain] = (now, result)
    if len(_intel_cache) > INTEL_CACHE_MAX:
        oldest = min(_intel_cache, key=lambda k: _intel_cache[k][0])
        del _intel_cache[oldest]

    return result

from fastapi.responses import FileResponse
import os
import tempfile

@app.post("/report")
@limiter.limit("5/minute")
async def generate_consolidated_report(request: Request, data: dict):
    target = data.get("target", "Target")
    
    # 1. Re-run Attack Surface Mapper (cheap, deterministic) to ensure we have the risk graph signals
    try:
        data["attack_surface"] = attack_surface_mapper.map_attack_surface(data)
    except Exception as e:
        data["attack_surface"] = {"error": str(e)}

    # 2. Re-run Intelligence Correlator (cheap, deterministic)
    try:
        data["intelligence"] = attack_surface_intelligence.generate_intelligence(data)
    except Exception as e:
        data["intelligence"] = []

    # 3. Structure for Report Generator
    report_input = {
        "target": target,
        "attack_surface": data.get("attack_surface"),
        "full_results": data,
        "intelligence": data.get("intelligence")
    }

    temp_dir = tempfile.gettempdir()
    # Sanitize filename
    safe_target = "".join([c for c in target if c.isalnum() or c in ['.','-']])
    filename = f"OpenRecon_Report_{safe_target}_{datetime.now().strftime('%Y%m%d')}.pdf"
    output_path = os.path.join(temp_dir, filename)
    
    result_path = report_generator.generate_report(report_input, output_path)
    
    if "Error" in result_path:
         return JSONResponse(status_code=500, content={"error": result_path})
         
    return FileResponse(result_path, filename=filename, media_type='application/pdf')

