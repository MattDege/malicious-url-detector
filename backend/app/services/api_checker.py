import os
import requests
import asyncio
import aiohttp
from typing import Dict, Optional, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class APIChecker:
    """
    Handles checking URLs against multiple threat intelligence APIs.
    """
    
    def __init__(self):
        """Initialize API checker with API keys from environment."""
        self.google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
        # API endpoints
        self.google_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.virustotal_url = "https://www.virustotal.com/api/v3/urls"
        self.urlhaus_url = "https://urlhaus-api.abuse.ch/v1/url/"
    
    async def check_all_apis(self, url: str) -> Dict:
        """
        Check URL against all available APIs concurrently.
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with results from all APIs
        """
        results = {
            "google_safe_browsing": {},
            "virustotal": {},
            "urlhaus": {},
            "summary": {}
        }
        
        # Run all API checks concurrently
        tasks = [
            self.check_google_safe_browsing(url),
            self.check_virustotal(url),
            self.check_urlhaus(url)
        ]
        
        api_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        results["google_safe_browsing"] = api_results[0] if not isinstance(api_results[0], Exception) else {"error": str(api_results[0])}
        results["virustotal"] = api_results[1] if not isinstance(api_results[1], Exception) else {"error": str(api_results[1])}
        results["urlhaus"] = api_results[2] if not isinstance(api_results[2], Exception) else {"error": str(api_results[2])}
        
        # Generate summary
        results["summary"] = self._generate_summary(results)
        
        return results
    
    async def check_google_safe_browsing(self, url: str) -> Dict:
        """
        Check URL against Google Safe Browsing API.
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with Google Safe Browsing results
        """
        if not self.google_api_key:
            return {"available": False, "error": "API key not configured"}
        
        payload = {
            "client": {
                "clientId": "malicious-url-scanner",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.google_url}?key={self.google_api_key}",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Check if threats found
                        if "matches" in data and data["matches"]:
                            threat_types = [match.get("threatType", "UNKNOWN") for match in data["matches"]]
                            return {
                                "available": True,
                                "safe": False,
                                "threats": threat_types,
                                "threat_count": len(threat_types),
                                "details": data
                            }
                        else:
                            return {
                                "available": True,
                                "safe": True,
                                "threats": [],
                                "threat_count": 0
                            }
                    else:
                        error_text = await response.text()
                        return {
                            "available": False,
                            "error": f"API returned status {response.status}: {error_text}"
                        }
        except asyncio.TimeoutError:
            return {"available": False, "error": "Request timed out"}
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    async def check_virustotal(self, url: str) -> Dict:
        """
        Check URL against VirusTotal API.
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with VirusTotal results
        """
        if not self.virustotal_api_key:
            return {"available": False, "error": "API key not configured"}
        
        headers = {
            "x-apikey": self.virustotal_api_key
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Submit URL for scanning
                async with session.post(
                    self.virustotal_url,
                    headers=headers,
                    data={"url": url},
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Get the analysis ID
                        analysis_id = data.get("data", {}).get("id")
                        
                        if analysis_id:
                            # Fetch analysis results
                            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                            async with session.get(
                                analysis_url,
                                headers=headers,
                                timeout=aiohttp.ClientTimeout(total=10),
                                ssl=False
                            ) as analysis_response:
                                if analysis_response.status == 200:
                                    analysis_data = await analysis_response.json()
                                    stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
                                    
                                    malicious = stats.get("malicious", 0)
                                    suspicious = stats.get("suspicious", 0)
                                    harmless = stats.get("harmless", 0)
                                    undetected = stats.get("undetected", 0)
                                    
                                    total_scans = malicious + suspicious + harmless + undetected
                                    detection_rate = (malicious + suspicious) / total_scans if total_scans > 0 else 0
                                    
                                    return {
                                        "available": True,
                                        "safe": malicious == 0 and suspicious == 0,
                                        "malicious_count": malicious,
                                        "suspicious_count": suspicious,
                                        "harmless_count": harmless,
                                        "undetected_count": undetected,
                                        "total_scans": total_scans,
                                        "detection_rate": round(detection_rate * 100, 2)
                                    }
                        
                        return {"available": True, "safe": True, "note": "No previous analysis available"}
                    else:
                        error_text = await response.text()
                        return {
                            "available": False,
                            "error": f"API returned status {response.status}: {error_text}"
                        }
        except asyncio.TimeoutError:
            return {"available": False, "error": "Request timed out"}
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    async def check_urlhaus(self, url: str) -> Dict:
        """
        Check URL against URLhaus API (free, no API key needed).
        
        Args:
            url: The URL to check
            
        Returns:
            Dictionary with URLhaus results
        """
        payload = {"url": url}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.urlhaus_url,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                 ssl=False  # Add this line
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        query_status = data.get("query_status")
                        
                        if query_status == "ok":
                            # URL found in URLhaus database
                            url_status = data.get("url_status")
                            threat_type = data.get("threat")
                            tags = data.get("tags", [])
                            
                            return {
                                "available": True,
                                "safe": False,
                                "in_database": True,
                                "url_status": url_status,
                                "threat_type": threat_type,
                                "tags": tags,
                                "details": data
                            }
                        elif query_status == "no_results":
                            # URL not found (good sign)
                            return {
                                "available": True,
                                "safe": True,
                                "in_database": False
                            }
                        else:
                            return {
                                "available": True,
                                "safe": True,
                                "note": f"Query status: {query_status}"
                            }
                    else:
                        return {
                            "available": False,
                            "error": f"API returned status {response.status}"
                        }
        except asyncio.TimeoutError:
            return {"available": False, "error": "Request timed out"}
        except Exception as e:
            return {"available": False, "error": str(e)}
    
    def _generate_summary(self, results: Dict) -> Dict:
        """
        Generate a summary of all API results.
        
        Args:
            results: Dictionary with all API results
            
        Returns:
            Summary dictionary
        """
        total_apis = 0
        apis_flagged = 0
        apis_safe = 0
        apis_unavailable = 0
        
        threat_indicators = []
        
        # Google Safe Browsing
        gsb = results.get("google_safe_browsing", {})
        if gsb.get("available"):
            total_apis += 1
            if not gsb.get("safe", True):
                apis_flagged += 1
                threat_indicators.append(f"Google: {', '.join(gsb.get('threats', []))}")
            else:
                apis_safe += 1
        else:
            apis_unavailable += 1
        
        # VirusTotal
        vt = results.get("virustotal", {})
        if vt.get("available"):
            total_apis += 1
            if not vt.get("safe", True):
                apis_flagged += 1
                threat_indicators.append(f"VirusTotal: {vt.get('malicious_count', 0)} vendors flagged")
            else:
                apis_safe += 1
        else:
            apis_unavailable += 1
        
        # URLhaus
        uh = results.get("urlhaus", {})
        if uh.get("available"):
            total_apis += 1
            if not uh.get("safe", True):
                apis_flagged += 1
                threat_type = uh.get("threat_type", "unknown")
                threat_indicators.append(f"URLhaus: {threat_type}")
            else:
                apis_safe += 1
        else:
            apis_unavailable += 1
        
        return {
            "total_apis_checked": total_apis,
            "apis_flagged_malicious": apis_flagged,
            "apis_marked_safe": apis_safe,
            "apis_unavailable": apis_unavailable,
            "threat_indicators": threat_indicators,
            "overall_assessment": "MALICIOUS" if apis_flagged > 0 else "SAFE"
        }


# Synchronous wrapper for backward compatibility
def check_url_with_apis(url: str) -> Dict:
    """
    Synchronous wrapper to check URL against all APIs.
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary with results from all APIs
    """
    checker = APIChecker()
    
    # Run async function in event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(checker.check_all_apis(url))
        return results
    finally:
        loop.close()