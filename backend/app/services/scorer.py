"""
Risk Scoring Service

This module combines results from API checks and ML feature analysis
to produce a final risk score and assessment for URLs.
"""

from typing import Dict, List, Tuple


class RiskScorer:
    """
    Combines multiple data sources to calculate final risk score.
    """
    
    # Score thresholds
    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 70
    
    # Weights for different components
    WEIGHTS = {
        'api_score': 0.70,      # 70% weight on API results
        'feature_score': 0.30,  # 30% weight on ML features
    }
    
    def calculate_risk_score(self, api_results: Dict, feature_results: Dict) -> Dict:
        """
        Calculate final risk score combining API and feature analysis.
        
        Args:
            api_results: Results from API checker
            feature_results: Results from feature analysis
            
        Returns:
            Dictionary with final score and detailed breakdown
        """
        # Get individual scores
        api_score = self._calculate_api_score(api_results)
        feature_score = feature_results.get('feature_risk_score', 0)
        
        # Calculate weighted final score
        final_score = (
            api_score * self.WEIGHTS['api_score'] +
            feature_score * self.WEIGHTS['feature_score']
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Get all threat indicators
        threat_indicators = self._collect_threat_indicators(
            api_results, 
            feature_results
        )
        
        # Get recommendations
        recommendations = self._generate_recommendations(
            risk_level, 
            threat_indicators
        )
        
        return {
            'final_score': round(final_score, 2),
            'risk_level': risk_level,
            'api_score': round(api_score, 2),
            'feature_score': round(feature_score, 2),
            'score_breakdown': {
                'api_contribution': round(api_score * self.WEIGHTS['api_score'], 2),
                'feature_contribution': round(feature_score * self.WEIGHTS['feature_score'], 2),
            },
            'threat_indicators': threat_indicators,
            'recommendations': recommendations,
            'confidence': self._calculate_confidence(api_results),
        }
    
    def _calculate_api_score(self, api_results: Dict) -> float:
        """
        Calculate risk score based on API results.
        
        Args:
            api_results: Results from API checker
            
        Returns:
            Risk score from 0-100
        """
        summary = api_results.get('summary', {})
        
        apis_checked = summary.get('total_apis_checked', 0)
        apis_flagged = summary.get('apis_flagged_malicious', 0)
        
        # If no APIs available, return neutral score
        if apis_checked == 0:
            return 50
        
        # Calculate score based on proportion of APIs that flagged URL
        flagged_ratio = apis_flagged / apis_checked
        
        # Scale to 0-100
        api_score = flagged_ratio * 100
        
        # Boost score if multiple APIs agree
        if apis_flagged > 1:
            api_score = min(api_score + (apis_flagged - 1) * 10, 100)
        
        return api_score
    
    def _determine_risk_level(self, score: float) -> str:
        """
        Determine risk level based on score.
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Risk level string
        """
        if score <= self.SAFE_THRESHOLD:
            return "SAFE"
        elif score <= self.SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        else:
            return "MALICIOUS"
    
    def _collect_threat_indicators(
        self, 
        api_results: Dict, 
        feature_results: Dict
    ) -> List[str]:
        """
        Collect all threat indicators from various sources.
        
        Args:
            api_results: Results from API checker
            feature_results: Results from feature analysis
            
        Returns:
            List of threat indicator strings
        """
        indicators = []
        
        # API threat indicators
        api_summary = api_results.get('summary', {})
        api_indicators = api_summary.get('threat_indicators', [])
        indicators.extend(api_indicators)
        
        # Feature-based threat indicators
        feature_risks = feature_results.get('risk_factors', [])
        indicators.extend(feature_risks)
        
        return indicators
    
    def _generate_recommendations(
        self, 
        risk_level: str, 
        threat_indicators: List[str]
    ) -> List[str]:
        """
        Generate safety recommendations based on risk level.
        
        Args:
            risk_level: The determined risk level
            threat_indicators: List of detected threats
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if risk_level == "SAFE":
            recommendations.append("URL appears safe to visit")
            recommendations.append("Standard security practices still apply")
            
        elif risk_level == "SUSPICIOUS":
            recommendations.append("Exercise caution when visiting this URL")
            recommendations.append("Verify the website's legitimacy before entering sensitive information")
            recommendations.append("Check for typos in the domain name")
            recommendations.append("Look for HTTPS and valid SSL certificate")
            
        else:  # MALICIOUS
            recommendations.append("⚠️ DO NOT visit this URL")
            recommendations.append("This URL has been flagged as malicious by security services")
            recommendations.append("Do not enter any personal or financial information")
            recommendations.append("Report this URL if you received it in an email or message")
        
        # Add specific recommendations based on threats
        if any('IP address' in indicator for indicator in threat_indicators):
            recommendations.append("Uses IP address instead of domain - potentially suspicious")
        
        if any('HTTPS' in indicator for indicator in threat_indicators):
            recommendations.append("Consider only visiting websites that use HTTPS")
        
        if any('redirect' in indicator.lower() for indicator in threat_indicators):
            recommendations.append("URL may attempt to redirect to a different site")
        
        return recommendations
    
    def _calculate_confidence(self, api_results: Dict) -> str:
        """
        Calculate confidence level based on available data.
        
        Args:
            api_results: Results from API checker
            
        Returns:
            Confidence level string
        """
        summary = api_results.get('summary', {})
        apis_checked = summary.get('total_apis_checked', 0)
        apis_flagged = summary.get('apis_flagged_malicious', 0)
        
        # High confidence if multiple APIs agree
        if apis_checked >= 2 and (apis_flagged == apis_checked or apis_flagged == 0):
            return "HIGH"
        elif apis_checked >= 2:
            return "MEDIUM"
        elif apis_checked == 1:
            return "LOW"
        else:
            return "VERY_LOW"
    
    def get_detailed_analysis(
        self, 
        url: str,
        api_results: Dict, 
        feature_results: Dict,
        risk_score: Dict
    ) -> Dict:
        """
        Get complete detailed analysis of URL.
        
        Args:
            url: The URL analyzed
            api_results: Results from API checker
            feature_results: Results from feature analysis
            risk_score: Calculated risk score
            
        Returns:
            Complete analysis dictionary
        """
        return {
            'url': url,
            'risk_assessment': {
                'score': risk_score['final_score'],
                'level': risk_score['risk_level'],
                'confidence': risk_score['confidence'],
            },
            'score_details': {
                'api_score': risk_score['api_score'],
                'feature_score': risk_score['feature_score'],
                'breakdown': risk_score['score_breakdown'],
            },
            'threats': {
                'count': len(risk_score['threat_indicators']),
                'indicators': risk_score['threat_indicators'],
            },
            'api_checks': {
                'google_safe_browsing': self._format_api_result(
                    api_results.get('google_safe_browsing', {})
                ),
                'virustotal': self._format_api_result(
                    api_results.get('virustotal', {})
                ),
                'urlhaus': self._format_api_result(
                    api_results.get('urlhaus', {})
                ),
                'summary': api_results.get('summary', {}),
            },
            'url_analysis': {
                'features_analyzed': feature_results.get('total_features', 0),
                'key_features': self._extract_key_features(feature_results),
                'risk_factors': feature_results.get('risk_factors', []),
            },
            'recommendations': risk_score['recommendations'],
        }
    
    def _format_api_result(self, api_result: Dict) -> Dict:
        """
        Format API result for display.
        
        Args:
            api_result: Raw API result
            
        Returns:
            Formatted result
        """
        if not api_result.get('available', False):
            return {
                'status': 'unavailable',
                'message': api_result.get('error', 'Service unavailable')
            }
        
        return {
            'status': 'checked',
            'safe': api_result.get('safe', True),
            'details': {k: v for k, v in api_result.items() 
                       if k not in ['available', 'error']}
        }
    
    def _extract_key_features(self, feature_results: Dict) -> Dict:
        """
        Extract key features for display.
        
        Args:
            feature_results: Full feature results
            
        Returns:
            Dictionary of key features
        """
        features = feature_results.get('features', {})
        
        return {
            'url_length': features.get('url_length', 0),
            'domain_length': features.get('domain_length', 0),
            'subdomain_count': features.get('subdomain_count', 0),
            'uses_https': bool(features.get('has_https', 0)),
            'is_ip_address': bool(features.get('is_ip_address', 0)),
            'suspicious_keywords': features.get('suspicious_keyword_count', 0),
            'url_entropy': round(features.get('url_entropy', 0), 2),
        }


def calculate_final_score(
    api_results: Dict, 
    feature_results: Dict
) -> Dict:
    """
    Convenience function to calculate final risk score.
    
    Args:
        api_results: Results from API checker
        feature_results: Results from feature analysis
        
    Returns:
        Final risk score and assessment
    """
    scorer = RiskScorer()
    return scorer.calculate_risk_score(api_results, feature_results)


def get_complete_analysis(
    url: str,
    api_results: Dict,
    feature_results: Dict
) -> Dict:
    """
    Convenience function to get complete URL analysis.
    
    Args:
        url: The URL being analyzed
        api_results: Results from API checker
        feature_results: Results from feature analysis
        
    Returns:
        Complete analysis report
    """
    scorer = RiskScorer()
    risk_score = scorer.calculate_risk_score(api_results, feature_results)
    return scorer.get_detailed_analysis(url, api_results, feature_results, risk_score)