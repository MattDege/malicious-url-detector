"""
ML-based URL analysis using feature extraction
"""
import re
from urllib.parse import urlparse
import pickle
import os
from typing import Dict


class MLModel:
    """
    Machine Learning model for URL feature extraction and analysis
    Uses rule-based scoring combined with trained model (if available)
    """
    
    def __init__(self):
        """Initialize the ML model"""
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load pre-trained model if available"""
        model_path = os.path.join(
            os.path.dirname(__file__),
            "../../data/trained_model.pkl"
        )
        
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("✓ Loaded pre-trained ML model")
            except Exception as e:
                print(f"⚠ Could not load model: {e}")
                self.model = None
        else:
            print("ℹ No pre-trained model found, using feature-based analysis only")
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze URL using feature extraction
        
        Args:
            url: The URL to analyze
        
        Returns:
            Dictionary containing ML analysis results
        """
        features = self.extract_features(url)
        risk_score = self.calculate_ml_risk(features)
        
        return {
            "features": features,
            "risk_score": risk_score,
            "confidence": self.get_confidence(features),
            "flags": self.get_suspicious_flags(features)
        }
    
    def extract_features(self, url: str) -> Dict:
        """
        Extract relevant features from URL
        
        Features include:
        - URL length
        - Number of special characters
        - Number of subdomains
        - TLD analysis
        - Suspicious patterns
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        features = {
            # Length features
            "url_length": len(url),
            "domain_length": len(domain),
            "path_length": len(path),
            
            # Character counts
            "dot_count": url.count('.'),
            "hyphen_count": url.count('-'),
            "underscore_count": url.count('_'),
            "slash_count": url.count('/'),
            "question_count": url.count('?'),
            "equals_count": url.count('='),
            "at_count": url.count('@'),
            "ampersand_count": url.count('&'),
            "exclamation_count": url.count('!'),
            "tilde_count": url.count('~'),
            "percent_count": url.count('%'),
            
            # Subdomain analysis
            "subdomain_count": domain.count('.'),
            
            # TLD
            "tld": domain.split('.')[-1] if '.' in domain else '',
            
            # Suspicious patterns
            "has_ip_address": bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)),
            "has_suspicious_tld": domain.endswith(('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz')),
            "has_port": ':' in domain,
            
            # Protocol
            "is_https": parsed.scheme == 'https',
            
            # Entropy (randomness)
            "domain_entropy": self.calculate_entropy(domain),
        }
        
        return features
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        import math
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return round(entropy, 2)
    
    def calculate_ml_risk(self, features: Dict) -> int:
        """
        Calculate risk score based on features
        Returns score from 0-100
        """
        risk = 0
        
        # Length-based risk
        if features["url_length"] > 75:
            risk += 15
        elif features["url_length"] > 54:
            risk += 10
        
        # Special character risk
        special_chars = (
            features["hyphen_count"] +
            features["underscore_count"] +
            features["at_count"] +
            features["percent_count"]
        )
        if special_chars > 5:
            risk += 20
        elif special_chars > 3:
            risk += 10
        
        # Subdomain risk
        if features["subdomain_count"] > 3:
            risk += 15
        elif features["subdomain_count"] > 2:
            risk += 8
        
        # IP address instead of domain
        if features["has_ip_address"]:
            risk += 25
        
        # Suspicious TLD
        if features["has_suspicious_tld"]:
            risk += 20
        
        # No HTTPS
        if not features["is_https"]:
            risk += 10
        
        # High entropy (random-looking domain)
        if features["domain_entropy"] > 4.5:
            risk += 15
        
        # Port specified (unusual)
        if features["has_port"]:
            risk += 10
        
        return min(risk, 100)  # Cap at 100
    
    def get_confidence(self, features: Dict) -> float:
        """Calculate confidence score for the prediction"""
        # Simple confidence based on number of features analyzed
        confidence = 0.85  # Base confidence
        
        if features["has_ip_address"] or features["has_suspicious_tld"]:
            confidence = 0.95  # High confidence for clear indicators
        
        return confidence
    
    def get_suspicious_flags(self, features: Dict) -> list:
        """Return list of suspicious indicators found"""
        flags = []
        
        if features["url_length"] > 75:
            flags.append("Unusually long URL")
        
        if features["has_ip_address"]:
            flags.append("Uses IP address instead of domain")
        
        if features["has_suspicious_tld"]:
            flags.append("Suspicious top-level domain")
        
        if features["subdomain_count"] > 3:
            flags.append("Excessive subdomains")
        
        if not features["is_https"]:
            flags.append("No HTTPS encryption")
        
        if features["domain_entropy"] > 4.5:
            flags.append("Random-looking domain name")
        
        special_chars = (
            features["hyphen_count"] +
            features["underscore_count"] +
            features["at_count"]
        )
        if special_chars > 5:
            flags.append("Excessive special characters")
        
        return flags
