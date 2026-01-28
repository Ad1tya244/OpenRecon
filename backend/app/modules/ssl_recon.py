import ssl
import socket
import datetime
from typing import Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app.core.config import settings

def analyze_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieves and analyzes the SSL certificate of the target.
    Performs a standard handshake without sending application data.
    """
    context = ssl.create_default_context()
    
    # We must not disable verification entirely if we want to check validity properly
    # typically, but for RECON, we might want to fetch even if verify fails (self-signed).
    # OpenRecon goal is to "detect" config. 
    # Let's try standard verification first.
    context.check_hostname = False # We will manually check or just capture data
    context.verify_mode = ssl.CERT_NONE # Get cert even if invalid

    try:
        # Create socket with timeout
        sock = socket.create_connection((domain, port), timeout=settings.SOCKET_TIMEOUT)
        
        with context.wrap_socket(sock, server_hostname=domain) as conn:
            # Get binary cert
            der_cert = conn.getpeercert(binary_form=True)
            if not der_cert:
                return {"valid": False, "error": "No certificate found"}

            # Parse with cryptography
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Extract basic info
            subject = {attr.oid._name: attr.value for attr in cert.subject}
            issuer = {attr.oid._name: attr.value for attr in cert.issuer}
            
            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
            
            # Time remaining
            now = datetime.datetime.now(datetime.timezone.utc)
            days_remaining = (valid_to - now).days
            is_expired = days_remaining < 0
            
            # Signature Algo
            signature_algorithm = cert.signature_algorithm_oid._name

            return {
                "valid": not is_expired, # Basic validity check based on dates
                "is_expired": is_expired,
                "days_remaining": days_remaining,
                "subject": subject,
                "issuer": issuer,
                "version": cert.version.name,
                "signature_algorithm": signature_algorithm,
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_to.isoformat(),
                "serial_number": str(cert.serial_number),
                "cipher_suite": conn.cipher()
            }

    except socket.timeout:
         return {"valid": False, "error": "Connection timed out"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
