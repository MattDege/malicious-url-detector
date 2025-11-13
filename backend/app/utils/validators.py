
import re
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional


def validate_url(url: str) -> Tuple[bool, str, str]:
 
    # Check if URL is empty or None
    if not url or not isinstance(url, str):
        return False, "", "URL cannot be empty"
    
    # Remove extra whitespace
    url = url.strip()
    
    if not url:
        return False, "", "URL cannot be empty"
    
    # Normalize URL (add http:// if missing)
    normalized = normalize_url(url)
    
    # Try to parse the URL
    try:
        parsed = urlparse(normalized)
    except Exception as e:
        return False, "", f"Invalid URL format: {str(e)}"
    
    # Check if scheme is valid
    if parsed.scheme not in ['http', 'https']:
        return False, "", "URL must use http or https protocol"
    
    # Check if domain exists
    if not parsed.netloc:
        return False, "", "URL must contain a valid domain"
    
    # Validate domain format
    domain = parsed.netloc
    if not is_valid_domain(domain):
        return False, "", "Invalid domain format"
    
    # Check for suspicious patterns
    if has_suspicious_patterns(normalized):
        # Still valid, but flag it (not blocking)
        pass
    
    return True, normalized, ""


def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding protocol if missing.
    
    Args:
        url: The URL to normalize
        
    Returns:
        Normalized URL with protocol
    """
    url = url.strip()
    
    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url


def extract_domain(url: str) -> Optional[str]:
    """
    Extract the domain from a URL.
    
    Args:
        url: The URL to extract domain from
        
    Returns:
        Domain name or None if invalid
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain if domain else None
    except Exception:
        return None


def is_valid_domain(domain: str) -> bool:
    """
    Check if a domain name is valid.
    
    Args:
        domain: The domain to validate
        
    Returns:
        Boolean indicating if domain is valid
    """
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Basic domain regex pattern
    # Matches: example.com, sub.example.com, example.co.uk
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    # Also allow IP addresses
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    
    if re.match(domain_pattern, domain) or re.match(ip_pattern, domain):
        # Additional check: domain should not be too long
        if len(domain) > 253:
            return False
        
        # Check each label (part between dots) is not too long
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                return False
        
        return True
    
    return False


def has_suspicious_patterns(url: str) -> bool:
    """
    Check if URL contains suspicious patterns.
    
    Args:
        url: The URL to check
        
    Returns:
        Boolean indicating if suspicious patterns found
    """
    suspicious_indicators = [
        r'@',  # @ symbol in URL (phishing technique)
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address instead of domain
        r'-.{2,}\.',  # Multiple dashes before TLD
        r'\d{5,}',  # Very long numbers
    ]
    
    for pattern in suspicious_indicators:
        if re.search(pattern, url):
            return True
    
    return False


def get_url_components(url: str) -> dict:
    """
    Extract all components of a URL.
    
    Args:
        url: The URL to parse
        
    Returns:
        Dictionary with URL components
    """
    try:
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'full_url': url
        }
    except Exception:
        return {}


def clean_url(url: str) -> str:
    """
    Clean and standardize a URL.
    
    Args:
        url: The URL to clean
        
    Returns:
        Cleaned URL
    """
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Remove any null bytes
    url = url.replace('\x00', '')
    
    # Normalize to lowercase for domain
    try:
        parsed = urlparse(url)
        # Lowercase domain only, preserve path case
        cleaned = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return cleaned
    except Exception:
        return url