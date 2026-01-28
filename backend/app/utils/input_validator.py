import re
import ipaddress
from typing import Optional
from pydantic import BaseModel

class ValidationResult(BaseModel):
    is_valid: bool
    input_type: str = "unknown" # 'domain', 'ipv4', 'email', 'invalid'
    normalized_input: Optional[str] = None
    error_message: Optional[str] = None
    is_public: bool = False

def validate_target(target: str) -> ValidationResult:
    """
    Validates and normalizes target input.
    Accepts: Domain, IPv4, Email.
    Rejects: URLs, Private/Internal IPs/Domains, Wildcards, Ports.
    
    Security:
    - No DNS resolution used (prevents timing attacks / DNS rebinding during validation).
    - Strict regex allowlists.
    - Uses ipaddress for robust IP parsing.
    """
    if not target:
        return ValidationResult(is_valid=False, error_message="Input cannot be empty")

    # 1. Normalize
    target = target.strip().lower()

    # 2. Reject URLs (Protocol, Path, Port characters)
    # Check for :// sequence
    if "://" in target:
        return ValidationResult(is_valid=False, error_message="URLs are not accepted. Please provide a hostname or IP.")
    
    # Check for path separators or params
    if any(char in target for char in ['/', '\\', '?', '#']):
        return ValidationResult(is_valid=False, error_message="Paths and parameters are not accepted.")
    
    # Check for ports (colon) - IPv6 uses colon, but requirement says IPv4 only.
    # We'll handle IPv4 checking next, which shouldn't have colons.
    # Domains shouldn't have colons in this tool (inputs are just hostnames).
    if ':' in target:
         return ValidationResult(is_valid=False, error_message="Ports or IPv6 are not accepted. Only IPv4 or Hostnames.")
         
    # Check for wildcards
    if '*' in target:
        return ValidationResult(is_valid=False, error_message="Wildcards are not accepted.")

    # 3. Try IPv4
    try:
        ip = ipaddress.IPv4Address(target)
        # Security: Reject Internal/Private
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
             return ValidationResult(
                 is_valid=False, 
                 input_type="ipv4", 
                 error_message="Internal, Private, or Restricted IP ranges are not allowed."
             )
        # Valid Public IPv4
        return ValidationResult(
            is_valid=True, 
            input_type="ipv4", 
            normalized_input=str(ip), 
            is_public=True
        )
    except ipaddress.AddressValueError:
        pass # Not an IP

    # 4. Try Email
    # Simple strict regex for email structure
    if '@' in target:
        email_pattern = re.compile(r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$')
        if email_pattern.match(target):
            # Extract domain to ensure it's not internal
            domain_part = target.split('@')[1]
            # Recursively validate the domain part? Or just basic check?
            # Let's do a basic check here to avoid infinite recursion issues if logic changes.
            if domain_part == 'localhost' or domain_part.endswith('.local') or domain_part.endswith('.internal'):
                 return ValidationResult(is_valid=False, input_type="email", error_message="Email uses internal domain.")
            
            return ValidationResult(
                is_valid=True,
                input_type="email",
                normalized_input=target,
                is_public=True
            )
        else:
             return ValidationResult(is_valid=False, input_type="email", error_message="Invalid email format.")

    # 5. Try Domain
    # Strict Allowlist Regex:
    # - Alphanumeric start/end per label
    # - Hyphens allowed in middle
    # - Must have TLD (at least one dot)
    # - No special chars
    domain_pattern = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
    
    if domain_pattern.match(target):
        # Security: Reject Localhost/Internal TLDs explicitly (redundant but safe)
        if target == 'localhost' or target.endswith('.local') or target.endswith('.internal') or target.endswith('.lan'):
            return ValidationResult(
                is_valid=False, 
                input_type="domain", 
                error_message="Local or internal domain rejected."
            )
            
        return ValidationResult(
            is_valid=True, 
            input_type="domain", 
            normalized_input=target, 
            is_public=True
        )

    # 6. Fallback
    return ValidationResult(
        is_valid=False, 
        input_type="invalid", 
        error_message="Invalid input format. Must be a valid public Domain, IPv4, or Email."
    )
