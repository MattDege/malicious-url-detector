"""
URL Feature Extraction Module

This module extracts features from URLs for machine learning analysis.
Features include URL structure, character patterns, domain properties, etc.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict
import tldextract


def extract_all_features(url: str) -> Dict:
    """
    Extract all features from a URL for ML analysis.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing all extracted features
    """
    parsed = urlparse(url)
    
    features = {
        # Basic length features
        **extract_length_features(url, parsed),
        
        # Character-based features
        **extract_character_features(url),
        
        # Domain features
        **extract_domain_features(url, parsed),
        
        # Path and query features
        **extract_path_features(parsed),
        
        # Special pattern features
        **extract_pattern_features(url, parsed),
        
        # Entropy features
        **extract_entropy_features(url),
    }
    
    return features


def extract_length_features(url: str, parsed) -> Dict:
    """
    Extract length-based features.
    
    Args:
        url: The URL string
        parsed: Parsed URL object
        
    Returns:
        Dictionary of length features
    """
    return {
        'url_length': len(url),
        'domain_length': len(parsed.netloc),
        'path_length': len(parsed.path),
        'query_length': len(parsed.query) if parsed.query else 0,
        'fragment_length': len(parsed.fragment) if parsed.fragment else 0,
    }


def extract_character_features(url: str) -> Dict:
    """
    Extract character-based features.
    
    Args:
        url: The URL string
        
    Returns:
        Dictionary of character features
    """
    return {
        'digit_count': sum(c.isdigit() for c in url),
        'letter_count': sum(c.isalpha() for c in url),
        'special_char_count': sum(not c.isalnum() for c in url),
        'dash_count': url.count('-'),
        'underscore_count': url.count('_'),
        'dot_count': url.count('.'),
        'slash_count': url.count('/'),
        'question_mark_count': url.count('?'),
        'equal_count': url.count('='),
        'at_count': url.count('@'),
        'ampersand_count': url.count('&'),
        'percent_count': url.count('%'),
        'uppercase_count': sum(c.isupper() for c in url),
        'digit_ratio': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
    }


def extract_domain_features(url: str, parsed) -> Dict:
    """
    Extract domain-related features.
    
    Args:
        url: The URL string
        parsed: Parsed URL object
        
    Returns:
        Dictionary of domain features
    """
    domain = parsed.netloc
    
    # Extract TLD information
    try:
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        tld = extracted.suffix
    except Exception:
        subdomain = ""
        domain_name = domain
        tld = ""
    
    # Count subdomains
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    
    # Check if IP address
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    
    return {
        'subdomain_count': subdomain_count,
        'subdomain_length': len(subdomain),
        'domain_name_length': len(domain_name),
        'tld_length': len(tld),
        'is_ip_address': 1 if is_ip else 0,
        'has_port': 1 if ':' in domain else 0,
        'tld_in_path': 1 if tld and tld in parsed.path else 0,
        'tld_in_subdomain': 1 if tld and tld in subdomain else 0,
    }


def extract_path_features(parsed) -> Dict:
    """
    Extract path and query features.
    
    Args:
        parsed: Parsed URL object
        
    Returns:
        Dictionary of path features
    """
    path = parsed.path
    query = parsed.query
    
    # Count path segments
    path_segments = [p for p in path.split('/') if p]
    
    # Count query parameters
    query_params = query.split('&') if query else []
    
    return {
        'path_segment_count': len(path_segments),
        'query_param_count': len(query_params),
        'has_query': 1 if query else 0,
        'has_fragment': 1 if parsed.fragment else 0,
        'max_path_segment_length': max([len(p) for p in path_segments], default=0),
        'avg_path_segment_length': sum([len(p) for p in path_segments]) / len(path_segments) if path_segments else 0,
    }


def extract_pattern_features(url: str, parsed) -> Dict:
    """
    Extract suspicious pattern features.
    
    Args:
        url: The URL string
        parsed: Parsed URL object
        
    Returns:
        Dictionary of pattern features
    """
    # Suspicious patterns
    has_double_slash = '//' in parsed.path
    has_at_symbol = '@' in url
    has_dash_in_domain = '-' in parsed.netloc
    
    # Count consecutive characters
    max_consecutive_digits = max([len(match.group()) for match in re.finditer(r'\d+', url)], default=0)
    max_consecutive_letters = max([len(match.group()) for match in re.finditer(r'[a-zA-Z]+', url)], default=0)
    
    # Suspicious keywords (common in phishing)
    suspicious_keywords = [
        'login', 'signin', 'account', 'update', 'confirm', 'verify', 
        'secure', 'banking', 'paypal', 'amazon', 'apple', 'microsoft',
        'password', 'suspended', 'locked', 'unusual'
    ]
    keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
    
    return {
        'has_double_slash_in_path': 1 if has_double_slash else 0,
        'has_at_symbol': 1 if has_at_symbol else 0,
        'has_dash_in_domain': 1 if has_dash_in_domain else 0,
        'max_consecutive_digits': max_consecutive_digits,
        'max_consecutive_letters': max_consecutive_letters,
        'suspicious_keyword_count': keyword_count,
        'has_https': 1 if parsed.scheme == 'https' else 0,
    }


def extract_entropy_features(url: str) -> Dict:
    """
    Extract entropy-based features (measures randomness).
    
    Args:
        url: The URL string
        
    Returns:
        Dictionary of entropy features
    """
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    parsed = urlparse(url)
    
    return {
        'url_entropy': calculate_entropy(url),
        'domain_entropy': calculate_entropy(parsed.netloc),
        'path_entropy': calculate_entropy(parsed.path) if parsed.path else 0,
    }


def get_feature_vector(url: str) -> list:
    """
    Get feature vector as a list (for ML model input).
    
    Args:
        url: The URL to analyze
        
    Returns:
        List of feature values in consistent order
    """
    features = extract_all_features(url)
    
    # Define consistent feature order
    feature_names = [
        'url_length', 'domain_length', 'path_length', 'query_length', 'fragment_length',
        'digit_count', 'letter_count', 'special_char_count', 'dash_count', 'underscore_count',
        'dot_count', 'slash_count', 'question_mark_count', 'equal_count', 'at_count',
        'ampersand_count', 'percent_count', 'uppercase_count', 'digit_ratio',
        'subdomain_count', 'subdomain_length', 'domain_name_length', 'tld_length',
        'is_ip_address', 'has_port', 'tld_in_path', 'tld_in_subdomain',
        'path_segment_count', 'query_param_count', 'has_query', 'has_fragment',
        'max_path_segment_length', 'avg_path_segment_length',
        'has_double_slash_in_path', 'has_at_symbol', 'has_dash_in_domain',
        'max_consecutive_digits', 'max_consecutive_letters', 'suspicious_keyword_count',
        'has_https', 'url_entropy', 'domain_entropy', 'path_entropy'
    ]
    
    return [features.get(name, 0) for name in feature_names]


def analyze_url_features(url: str) -> Dict:
    """
    Analyze URL and return feature summary with risk indicators.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary with features and risk indicators
    """
    features = extract_all_features(url)
    
    # Calculate risk indicators based on features
    risk_score = 0
    risk_factors = []
    
    # Long URL
    if features['url_length'] > 75:
        risk_score += 10
        risk_factors.append("Unusually long URL")
    
    # IP address instead of domain
    if features['is_ip_address']:
        risk_score += 20
        risk_factors.append("Uses IP address instead of domain name")
    
    # @ symbol (redirecting technique)
    if features['has_at_symbol']:
        risk_score += 25
        risk_factors.append("Contains @ symbol (possible redirect)")
    
    # Many subdomains
    if features['subdomain_count'] > 3:
        risk_score += 15
        risk_factors.append("Excessive subdomains")
    
    # Suspicious keywords
    if features['suspicious_keyword_count'] > 2:
        risk_score += 15
        risk_factors.append("Contains multiple suspicious keywords")
    
    # High digit ratio
    if features['digit_ratio'] > 0.3:
        risk_score += 10
        risk_factors.append("High proportion of digits")
    
    # No HTTPS
    if not features['has_https']:
        risk_score += 5
        risk_factors.append("Not using HTTPS")
    
    # High entropy (random-looking)
    if features['url_entropy'] > 5.0:
        risk_score += 10
        risk_factors.append("High entropy (random-looking URL)")
    
    return {
        'features': features,
        'feature_risk_score': min(risk_score, 100),
        'risk_factors': risk_factors,
        'total_features': len(features)
    }