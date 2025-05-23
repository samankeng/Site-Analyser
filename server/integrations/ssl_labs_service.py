# backend/integrations/ssl_labs_service.py

import logging
import os
import time
import requests
from django.conf import settings
from django.core.cache import cache
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SSLLabsService:
    """
    Service for integrating with SSL Labs API to perform 
    comprehensive SSL/TLS assessments
    """
    
    def __init__(self):
        self.api_base_url = "https://api.ssllabs.com/api/v3"
        self.cache_timeout = 86400  # 24 hours
        self.mock_enabled = getattr(settings, 'SSL_LABS_MOCK_ENABLED', True)
        self.max_poll_attempts = 60  # Maximum number of poll attempts
        self.poll_interval = 10  # Seconds between polls
    
    def analyze_ssl(self, target_url):
        """
        Analyze SSL/TLS configuration using SSL Labs API
        
        Args:
            target_url (str): URL of the target to scan
            
        Returns:
            dict: SSL Labs assessment results
        """
        # Extract hostname from URL
        hostname = self._extract_hostname(target_url)
        if not hostname:
            logger.error(f"Could not extract valid hostname from {target_url}")
            return {"error": "Invalid URL", "data": None}
        
        # Check cache first
        cache_key = f"ssllabs_{hostname}"
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Using cached SSL Labs data for {hostname}")
            return cached_data
        
        # If mock mode is enabled, return mock data
        if self.mock_enabled:
            logger.info(f"Using mock SSL Labs data for {hostname}")
            data = self._get_mock_ssl_data(hostname)
            cache.set(cache_key, data, self.cache_timeout)
            return data
        
        # Start the assessment
        try:
            # Initiate the scan
            logger.info(f"Starting SSL Labs scan for {hostname}")
            start_new = "on"  # Always start a new scan
            
            start_response = requests.get(
                f"{self.api_base_url}/analyze",
                params={
                    "host": hostname,
                    "startNew": start_new,
                    "all": "done",  # Return all the assessment results
                    "ignoreMismatch": "on"  # Continue assessments even if server certificate doesn't match hostname
                },
                timeout=30
            )
            
            if start_response.status_code != 200:
                logger.error(f"SSL Labs API error: {start_response.status_code} - {start_response.text}")
                return {"error": f"API error: {start_response.status_code}", "data": None}
            
            # Poll for results
            assessment = start_response.json()
            poll_attempts = 0
            
            while assessment.get("status") != "READY" and assessment.get("status") != "ERROR" and poll_attempts < self.max_poll_attempts:
                logger.info(f"SSL Labs scan status for {hostname}: {assessment.get('status')}")
                time.sleep(self.poll_interval)
                
                poll_response = requests.get(
                    f"{self.api_base_url}/analyze",
                    params={
                        "host": hostname,
                        "all": "done"
                    },
                    timeout=30
                )
                
                if poll_response.status_code != 200:
                    logger.error(f"SSL Labs API error during polling: {poll_response.status_code} - {poll_response.text}")
                    return {"error": f"API polling error: {poll_response.status_code}", "data": None}
                
                assessment = poll_response.json()
                poll_attempts += 1
            
            # Check if the assessment completed successfully
            if assessment.get("status") == "READY":
                logger.info(f"SSL Labs scan completed for {hostname}")
                # Cache the successful response
                cache.set(cache_key, {"error": None, "data": assessment}, self.cache_timeout)
                return {"error": None, "data": assessment}
            else:
                logger.error(f"SSL Labs scan didn't complete in time or encountered an error: {assessment.get('status')}")
                return {"error": f"Scan not completed: {assessment.get('status')}", "data": assessment}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error requesting SSL Labs assessment: {str(e)}")
            return {"error": str(e), "data": None}
    
    def get_grade(self, target_url):
        """
        Get SSL Labs grade for a target
        
        Args:
            target_url (str): URL of the target
            
        Returns:
            str: SSL Labs grade (e.g., A+, A, B, C, etc.)
        """
        result = self.analyze_ssl(target_url)
        
        if result["error"] or not result["data"]:
            return "Unknown"
        
        try:
            # Get the best grade from all endpoints
            endpoints = result["data"].get("endpoints", [])
            if not endpoints:
                return "Unknown"
            
            grades = [ep.get("grade", "Unknown") for ep in endpoints if "grade" in ep]
            if not grades:
                return "Unknown"
            
            # Return the lowest grade (worst security)
            # Sort grades in security order: A+ > A > A- > B > C > ...
            grade_order = {
                "A+": 0, "A": 1, "A-": 2, 
                "B+": 3, "B": 4, "B-": 5,
                "C+": 6, "C": 7, "C-": 8,
                "D+": 9, "D": 10, "D-": 11,
                "E+": 12, "E": 13, "E-": 14,
                "F+": 15, "F": 16, "F-": 17,
                "T": 18,  # Trust issues
                "M": 19,  # Certificate name mismatch
                "Unknown": 20
            }
            
            return sorted(grades, key=lambda g: grade_order.get(g, 100))[-1]
            
        except Exception as e:
            logger.error(f"Error extracting SSL Labs grade: {str(e)}")
            return "Error"
    
    def _extract_hostname(self, url):
        """Extract hostname from URL"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            # If no hostname was found, the URL might be missing the scheme
            if not hostname and parsed.path:
                # Try adding https:// and parse again
                parsed = urlparse(f"https://{url}")
                hostname = parsed.netloc
            
            # Remove port if present
            if ":" in hostname:
                hostname = hostname.split(":")[0]
                
            return hostname
        except Exception as e:
            logger.error(f"Error extracting hostname from URL {url}: {str(e)}")
            return None
    
    def _get_mock_ssl_data(self, hostname):
        """Generate mock SSL Labs assessment data for development/testing"""
        # Create a deterministic but varied response based on hostname
        hostname_hash = sum(ord(c) for c in hostname) % 100
        
        # Determine grade based on hostname hash
        grades = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "F"]
        grade_index = hostname_hash % len(grades)
        grade = grades[grade_index]
        
        # Generate mock cipher suites
        cipher_suites = [
            {
                "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "cipherStrength": 256
            },
            {
                "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "cipherStrength": 128
            },
            {
                "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "cipherStrength": 256
            },
            {
                "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "cipherStrength": 128
            }
        ]
        
        # Add a weak cipher for lower grades
        if grade_index > 5:
            cipher_suites.append({
                "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "cipherStrength": 112
            })
        
        # Choose protocols based on grade
        protocols = []
        if grade_index < 4:  # A+, A, A-, B+
            protocols = [
                {"name": "TLS", "version": "1.3", "enabled": True},
                {"name": "TLS", "version": "1.2", "enabled": True}
            ]
        elif grade_index < 6:  # B, B-, C+
            protocols = [
                {"name": "TLS", "version": "1.2", "enabled": True},
                {"name": "TLS", "version": "1.1", "enabled": True},
                {"name": "TLS", "version": "1.0", "enabled": True}
            ]
        else:  # C, F
            protocols = [
                {"name": "TLS", "version": "1.2", "enabled": True},
                {"name": "TLS", "version": "1.1", "enabled": True},
                {"name": "TLS", "version": "1.0", "enabled": True},
                {"name": "SSL", "version": "3.0", "enabled": True}
            ]
        
        # Create a certificate with varying expiration
        days_valid = 30 + (hostname_hash * 10)
        
        # Build mock endpoints
        endpoints = [
            {
                "ipAddress": f"192.168.1.{hostname_hash % 255}",
                "grade": grade,
                "hasWarnings": grade_index > 4,
                "details": {
                    "protocols": protocols,
                    "suites": [{"list": cipher_suites}],
                    "cert": {
                        "subject": f"CN={hostname}",
                        "issuer": "CN=Mock CA",
                        "validFrom": 1609459200,  # January 1, 2021
                        "validTo": int(time.time()) + (days_valid * 86400),
                        "keyAlg": "RSA",
                        "keySize": 2048 if grade_index < 5 else 1024
                    },
                    "serverSignature": "Apache/2.4.41 (Ubuntu)",
                    "vulnBeast": grade_index > 6,
                    "heartbleed": grade_index > 7,
                    "secureRenegotiation": grade_index < 6
                }
            }
        ]
        
        # Build full mock response
        mock_response = {
            "host": hostname,
            "port": 443,
            "protocol": "https",
            "status": "READY",
            "startTime": int(time.time()) - 300,  # 5 minutes ago
            "testTime": int(time.time()),
            "engineVersion": "Mock SSL Labs 1.0.0",
            "criteriaVersion": "Mock 2024",
            "endpoints": endpoints
        }
        
        return {"error": None, "data": mock_response}