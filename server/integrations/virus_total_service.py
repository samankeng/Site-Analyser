# backend/integrations/virus_total_service.py

import logging
import os
import requests
import hashlib
import time
import re
from django.conf import settings
from django.core.cache import cache
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class VirusTotalService:
    """
    Service for integrating with VirusTotal API to check website safety and reputation
    """
    
    def __init__(self):
        # Get API key from settings or environment variables
        self.api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', os.environ.get('VIRUSTOTAL_API_KEY'))
        self.api_base_url = "https://www.virustotal.com/api/v3"
        self.cache_timeout = 86400  # 24 hours
        self.mock_enabled = getattr(settings, 'VIRUSTOTAL_MOCK_ENABLED', True)
        
        if not self.api_key and not self.mock_enabled:
            logger.warning("No VirusTotal API key found. Set VIRUSTOTAL_API_KEY in settings or environment.")
    
    def scan_url(self, target_url):
        """
        Scan a URL with VirusTotal
        
        Args:
            target_url (str): URL to scan
            
        Returns:
            dict: Scan results from VirusTotal
        """
        # Normalize the URL for consistent caching
        normalized_url = self._normalize_url(target_url)
        if not normalized_url:
            logger.error(f"Could not normalize URL: {target_url}")
            return {"error": "Invalid URL", "data": None}
        
        # Check cache first
        cache_key = f"virustotal_url_{hashlib.md5(normalized_url.encode()).hexdigest()}"
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Using cached VirusTotal data for {normalized_url}")
            return cached_data
        
        # If mock mode is enabled, return mock data
        if self.mock_enabled:
            logger.info(f"Using mock VirusTotal data for {normalized_url}")
            data = self._get_mock_url_data(normalized_url)
            cache.set(cache_key, data, self.cache_timeout)
            return data
        
        # Otherwise, query the VirusTotal API
        if not self.api_key:
            return {"error": "No VirusTotal API key configured", "data": None}
        
        try:
            # First submit URL for analysis
            headers = {
                "x-apikey": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {"url": normalized_url}
            
            submit_response = requests.post(
                f"{self.api_base_url}/urls",
                headers=headers,
                data=data,
                timeout=30
            )
            
            if submit_response.status_code != 200:
                logger.error(f"VirusTotal API error: {submit_response.status_code} - {submit_response.text}")
                return {"error": f"API error: {submit_response.status_code}", "data": None}
            
            # Extract analysis ID from response
            analysis_id = submit_response.json().get("data", {}).get("id")
            if not analysis_id:
                logger.error("No analysis ID returned from VirusTotal")
                return {"error": "No analysis ID returned", "data": None}
            
            # Wait for analysis to complete
            time.sleep(5)  # Brief delay to let analysis start
            
            # Check analysis results
            analysis_url = f"{self.api_base_url}/analyses/{analysis_id}"
            analysis_response = requests.get(
                analysis_url,
                headers={"x-apikey": self.api_key},
                timeout=30
            )
            
            if analysis_response.status_code != 200:
                logger.error(f"VirusTotal analysis API error: {analysis_response.status_code} - {analysis_response.text}")
                return {"error": f"Analysis API error: {analysis_response.status_code}", "data": None}
            
            analysis_data = analysis_response.json()
            
            # Cache the results
            cache.set(cache_key, {"error": None, "data": analysis_data}, self.cache_timeout)
            return {"error": None, "data": analysis_data}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error requesting VirusTotal analysis: {str(e)}")
            return {"error": str(e), "data": None}
    
    def get_domain_report(self, target_url):
        """
        Get a domain report from VirusTotal
        
        Args:
            target_url (str): URL of the target
            
        Returns:
            dict: Domain report from VirusTotal
        """
        # Extract domain from URL
        domain = self._extract_domain(target_url)
        if not domain:
            logger.error(f"Could not extract valid domain from {target_url}")
            return {"error": "Invalid URL", "data": None}
        
        # Check cache first
        cache_key = f"virustotal_domain_{domain}"
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Using cached VirusTotal domain data for {domain}")
            return cached_data
        
        # If mock mode is enabled, return mock data
        if self.mock_enabled:
            logger.info(f"Using mock VirusTotal domain data for {domain}")
            data = self._get_mock_domain_data(domain)
            cache.set(cache_key, data, self.cache_timeout)
            return data
        
        # Otherwise, query the VirusTotal API
        if not self.api_key:
            return {"error": "No VirusTotal API key configured", "data": None}
        
        try:
            # Query domain report API
            headers = {"x-apikey": self.api_key}
            
            response = requests.get(
                f"{self.api_base_url}/domains/{domain}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"VirusTotal domain API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}", "data": None}
            
            domain_data = response.json()
            
            # Cache the results
            cache.set(cache_key, {"error": None, "data": domain_data}, self.cache_timeout)
            return {"error": None, "data": domain_data}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error requesting VirusTotal domain report: {str(e)}")
            return {"error": str(e), "data": None}
    
    def get_safety_score(self, target_url):
        """
        Get a safety score for a URL (0-100, higher is safer)
        
        Args:
            target_url (str): URL to check
            
        Returns:
            dict: Safety score and details
        """
        # First try to get domain report
        domain_report = self.get_domain_report(target_url)
        
        # Then get URL-specific scan
        url_scan = self.scan_url(target_url)
        
        # Calculate safety score
        try:
            score = 100  # Start with perfect score
            reasons = []
            
            # Process domain data if available
            if not domain_report["error"] and domain_report["data"]:
                domain_data = domain_report["data"]
                
                # Check for malicious ratings from security vendors
                attributes = domain_data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                
                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                total_engines = sum(last_analysis_stats.values())
                
                if total_engines > 0:
                    malicious_percentage = (malicious_count + suspicious_count) / total_engines
                    
                    # Deduct points based on percentage of engines flagging as malicious
                    score_deduction = malicious_percentage * 100
                    score -= score_deduction
                    
                    if malicious_count > 0:
                        reasons.append(f"{malicious_count} security vendors flagged the domain as malicious")
                    
                    if suspicious_count > 0:
                        reasons.append(f"{suspicious_count} security vendors flagged the domain as suspicious")
                
                # Check for recent detected URLs on the domain
                detected_urls = attributes.get("last_detected_urls", [])
                if len(detected_urls) > 10:
                    score -= 20
                    reasons.append(f"Domain has {len(detected_urls)} recently detected malicious URLs")
                elif len(detected_urls) > 0:
                    score -= len(detected_urls) * 2
                    reasons.append(f"Domain has {len(detected_urls)} recently detected malicious URLs")
            
            # Process URL-specific scan data if available
            if not url_scan["error"] and url_scan["data"]:
                url_data = url_scan["data"]
                
                # Check URL-specific analysis stats
                attributes = url_data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("stats", {})
                
                malicious_count = last_analysis_stats.get("malicious", 0)
                suspicious_count = last_analysis_stats.get("suspicious", 0)
                total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0
                
                if total_engines > 0:
                    malicious_percentage = (malicious_count + suspicious_count) / total_engines
                    
                    # Deduct points based on percentage of engines flagging as malicious
                    score_deduction = malicious_percentage * 100
                    score -= score_deduction
                    
                    if malicious_count > 0:
                        reasons.append(f"{malicious_count} security vendors flagged this specific URL as malicious")
                
            # Ensure score is within bounds
            score = max(0, min(100, score))
            
            return {
                "score": round(score),
                "is_safe": score >= 80,
                "risk_level": self._get_risk_level(score),
                "reasons": reasons
            }
            
        except Exception as e:
            logger.error(f"Error calculating safety score: {str(e)}")
            return {
                "score": 50,  # Neutral score if error
                "is_safe": None,  # Unknown safety
                "risk_level": "unknown",
                "reasons": ["Error calculating safety score"]
            }
    
    def _get_risk_level(self, score):
        """Convert numerical score to risk level"""
        if score >= 90:
            return "very low"
        elif score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "very high"
    
    def _normalize_url(self, url):
        """Normalize URL for consistent caching and queries"""
        try:
            parsed = urlparse(url)
            
            # If no scheme, add https://
            if not parsed.scheme:
                url = f"https://{url}"
                parsed = urlparse(url)
            
            # Ensure we have a hostname
            if not parsed.netloc:
                return None
            
            # Reconstruct URL with only scheme, netloc, and path
            path = parsed.path or "/"
            return f"{parsed.scheme}://{parsed.netloc}{path}"
            
        except Exception as e:
            logger.error(f"Error normalizing URL {url}: {str(e)}")
            return None
    
    def _extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            
            if not parsed.netloc:
                # Try adding https:// and parse again
                parsed = urlparse(f"https://{url}")
            
            domain = parsed.netloc
            
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # Validate domain format (basic check)
            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
                return domain
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting domain from URL {url}: {str(e)}")
            return None
    
    def _get_mock_url_data(self, url):
        """Generate mock VirusTotal URL scan data for development/testing"""
        # Create a deterministic but varied response based on URL
        url_hash = sum(ord(c) for c in url) % 100
        
        # Generate mock scan stats
        total_engines = 80
        malicious = url_hash % 7  # 0-6 malicious detections
        suspicious = url_hash % 4  # 0-3 suspicious detections
        
        # Generate analysis date
        analysis_date = int(time.time()) - (url_hash * 100)  # Varied times in the past
        
        # Build mock response
        mock_response = {
            "data": {
                "attributes": {
                    "date": analysis_date,
                    "stats": {
                        "harmless": total_engines - malicious - suspicious,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "undetected": 0,
                        "timeout": 0
                    },
                    "status": "completed",
                    "url": url
                },
                "id": f"mock-{hashlib.md5(url.encode()).hexdigest()}",
                "type": "analysis"
            },
            "meta": {
                "url_info": {
                    "url": url
                }
            }
        }
        
        return {"error": None, "data": mock_response}
    
    def _get_mock_domain_data(self, domain):
        """Generate mock VirusTotal domain report data for development/testing"""
        # Create a deterministic but varied response based on domain
        domain_hash = sum(ord(c) for c in domain) % 100
        
        # Generate varied numbers based on domain hash
        creation_date = int(time.time()) - (86400 * 365 * (1 + (domain_hash % 10)))  # 1-10 years ago
        reputation = domain_hash - 50  # Score from -50 to 49
        
        # Number of security vendors that flagged the domain
        harmless_count = 40 + (domain_hash % 30)  # 40-69 harmless verdicts
        malicious_count = domain_hash % 8  # 0-7 malicious verdicts
        suspicious_count = domain_hash % 5  # 0-4 suspicious verdicts
        total_count = harmless_count + malicious_count + suspicious_count + 10  # Add 10 for undetected
        
        # Create mock category
        categories = ["business", "shopping", "news", "technology", "adult", "games", "education"]
        category = categories[domain_hash % len(categories)]
        
        # Generate some detected URLs (more for higher domain hash values)
        detected_urls_count = 0
        if domain_hash > 80:
            detected_urls_count = 20 + (domain_hash % 20)
        elif domain_hash > 60:
            detected_urls_count = 5 + (domain_hash % 15)
        elif domain_hash > 40:
            detected_urls_count = domain_hash % 5
        
        detected_urls = []
        for i in range(detected_urls_count):
            detected_urls.append({
                "url": f"https://{domain}/path{i}/malicious.php",
                "detection_time": int(time.time()) - (86400 * (i + 1))
            })
        
        # Build mock response
        mock_response = {
            "data": {
                "attributes": {
                    "creation_date": creation_date,
                    "last_update_date": int(time.time()) - (86400 * (domain_hash % 30)),
                    "reputation": reputation,
                    "registrar": "Mock Registrar Inc.",
                    "last_analysis_stats": {
                        "harmless": harmless_count,
                        "malicious": malicious_count,
                        "suspicious": suspicious_count,
                        "undetected": 10
                    },
                    "categories": {
                        "Alexa": category,
                        "MockVendor": category
                    },
                    "last_detected_urls": detected_urls
                },
                "id": domain,
                "type": "domain"
            }
        }
        
        return {"error": None, "data": mock_response}