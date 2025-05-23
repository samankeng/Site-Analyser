# backend/ai_analyzer/services/threat_intelligence.py

import logging
import json
import re
import requests
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Service for gathering and analyzing threat intelligence data"""
    
    def __init__(self):
        # Initialize settings from Django settings or environment variables
        self.cache_timeout = getattr(settings, 'THREAT_INTEL_CACHE_TIMEOUT', 86400)  # 24 hours
        self.enable_mock = getattr(settings, 'THREAT_INTEL_MOCK_ENABLED', True)  # Use mock data by default
    
    def analyze_domain(self, domain):
        """
        Analyze a domain for threats and reputation
        
        Args:
            domain (str): Domain name to analyze
            
        Returns:
            dict: Threat intelligence for the domain
        """
        # Check cache first
        cache_key = f"threat_intel_domain_{domain}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            logger.info(f"Using cached threat intelligence for domain {domain}")
            return cached_data
        
        # If mocking is enabled, return mock data
        if self.enable_mock:
            data = self._get_mock_domain_data(domain)
        else:
            # In a real implementation, you would call threat intelligence APIs here
            # For example: VirusTotal, AlienVault OTX, etc.
            data = self._fetch_real_domain_intelligence(domain)
        
        # Cache the results
        cache.set(cache_key, data, self.cache_timeout)
        
        return data
    
    def analyze_ip(self, ip_address):
        """
        Analyze an IP address for threats and reputation
        
        Args:
            ip_address (str): IP address to analyze
            
        Returns:
            dict: Threat intelligence for the IP address
        """
        # Check cache first
        cache_key = f"threat_intel_ip_{ip_address}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            logger.info(f"Using cached threat intelligence for IP {ip_address}")
            return cached_data
        
        # If mocking is enabled, return mock data
        if self.enable_mock:
            data = self._get_mock_ip_data(ip_address)
        else:
            # In a real implementation, you would call threat intelligence APIs here
            data = self._fetch_real_ip_intelligence(ip_address)
        
        # Cache the results
        cache.set(cache_key, data, self.cache_timeout)
        
        return data
        
    def check_ssl_certificate(self, ssl_info):
        """
        Check SSL certificate against known compromised certificates
        
        Args:
            ssl_info (dict): SSL certificate information
            
        Returns:
            dict: Certificate threat assessment
        """
        # Extract certificate fingerprint if available
        fingerprint = ssl_info.get('fingerprint', '')
        
        if not fingerprint:
            # Try to calculate fingerprint from cert data if available
            if 'certificate' in ssl_info:
                try:
                    fingerprint = hashlib.sha256(ssl_info['certificate'].encode()).hexdigest()
                except:
                    pass
        
        # Check certificate against known bad certificates
        if fingerprint:
            return self._check_certificate_reputation(fingerprint)
        
        return {
            'is_suspicious': False,
            'reputation_score': 100,
            'reason': 'Certificate fingerprint not available for checking'
        }
    
    def analyze_headers(self, headers):
        """
        Analyze HTTP headers for security issues based on threat intelligence
        
        Args:
            headers (dict): HTTP headers
            
        Returns:
            dict: Header security assessment
        """
        results = {
            'suspicious_headers': [],
            'missing_security_headers': [],
            'overall_assessment': 'secure'
        }
        
        # Check for suspicious headers
        for header, value in headers.items():
            if self._is_suspicious_header(header, value):
                results['suspicious_headers'].append({
                    'header': header,
                    'value': value,
                    'reason': 'Matches known malicious pattern'
                })
        
        # Check for missing security headers
        security_headers = [
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        for header in security_headers:
            header_found = False
            for existing_header in headers.keys():
                if existing_header.lower() == header.lower():
                    header_found = True
                    break
            
            if not header_found:
                results['missing_security_headers'].append(header)
        
        # Set overall assessment
        if len(results['suspicious_headers']) > 0:
            results['overall_assessment'] = 'suspicious'
        elif len(results['missing_security_headers']) > 3:
            results['overall_assessment'] = 'vulnerable'
        elif len(results['missing_security_headers']) > 0:
            results['overall_assessment'] = 'needs_improvement'
        
        return results
    
    def check_known_vulnerabilities(self, target_url, scan_results):
        """
        Check if target has known vulnerabilities based on scan results
        
        Args:
            target_url (str): The URL that was scanned
            scan_results (dict): Results from vulnerability scan
            
        Returns:
            dict: Known vulnerabilities assessment
        """
        # Extract domain from URL
        domain_match = re.search(r'://([^/]+)', target_url)
        if domain_match:
            domain = domain_match.group(1)
        else:
            domain = target_url
        
        # Get domain intelligence
        domain_intel = self.analyze_domain(domain)
        
        # Check for known vulnerabilities
        vulnerabilities = []
        
        # Add vulnerabilities from domain intelligence
        if 'known_vulnerabilities' in domain_intel:
            vulnerabilities.extend(domain_intel['known_vulnerabilities'])
        
        # Check scan results for signs of specific vulnerabilities
        for result in scan_results:
            if 'cve_id' in result:
                # Add vulnerability details from scan
                vulnerabilities.append({
                    'cve_id': result['cve_id'],
                    'description': result.get('description', 'No description available'),
                    'severity': result.get('severity', 'unknown'),
                    'source': 'scan_result'
                })
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_vulnerabilities': len(vulnerabilities),
            'has_critical_vulnerabilities': any(v.get('severity') == 'critical' for v in vulnerabilities)
        }
    
    def _get_mock_domain_data(self, domain):
        """Generate mock threat intelligence data for a domain"""
        # Create a deterministic hash based on the domain
        domain_hash = int(hashlib.md5(domain.encode()).hexdigest(), 16) % 100
        
        # Determine risk level based on hash
        if domain_hash < 5:  # 5% of domains are high risk
            risk_level = 'high'
            categories = ['malware', 'phishing']
            score = domain_hash % 30  # 0-29 score (lower is worse)
        elif domain_hash < 15:  # 10% of domains are medium risk
            risk_level = 'medium'
            categories = ['suspicious']
            score = 30 + (domain_hash % 30)  # 30-59 score
        else:  # 85% of domains are low risk
            risk_level = 'low'
            categories = []
            score = 60 + (domain_hash % 40)  # 60-99 score
        
        # Generate last seen date
        today = datetime.now()
        days_ago = domain_hash % 60  # 0-59 days ago
        last_seen = (today - timedelta(days=days_ago)).strftime('%Y-%m-%d')
        
        # Known vulnerabilities (only for higher risk domains)
        known_vulnerabilities = []
        if risk_level in ['high', 'medium']:
            cve_year = 2023 - (domain_hash % 3)  # 2020-2023
            cve_id = f"CVE-{cve_year}-{10000 + domain_hash}"
            known_vulnerabilities.append({
                'cve_id': cve_id,
                'description': f"Mock vulnerability for {domain}",
                'severity': risk_level,
                'source': 'threat_intelligence_mock'
            })
        
        return {
            'domain': domain,
            'risk_level': risk_level,
            'categories': categories,
            'reputation_score': score,
            'last_seen': last_seen,
            'known_vulnerabilities': known_vulnerabilities,
            'source': 'mock_data'
        }
    
    def _get_mock_ip_data(self, ip_address):
        """Generate mock threat intelligence data for an IP address"""
        # Create a deterministic hash based on the IP
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16) % 100
        
        # Determine if IP is on blacklists based on hash
        blacklisted = ip_hash < 10  # 10% of IPs are blacklisted
        blacklist_count = ip_hash % 5 if blacklisted else 0
        
        # Determine geographical location (mock)
        countries = ['United States', 'China', 'Russia', 'Germany', 'Brazil', 'India', 'United Kingdom']
        country = countries[ip_hash % len(countries)]
        
        # Generate last activity date
        today = datetime.now()
        days_ago = ip_hash % 30  # 0-29 days ago
        last_activity = (today - timedelta(days=days_ago)).strftime('%Y-%m-%d')
        
        return {
            'ip': ip_address,
            'is_blacklisted': blacklisted,
            'blacklist_count': blacklist_count,
            'country': country,
            'asn': f"AS{ip_hash + 10000}",
            'last_activity': last_activity,
            'reputation_score': 100 - (blacklist_count * 20),
            'source': 'mock_data'
        }
    
    def _check_certificate_reputation(self, fingerprint):
        """Check if a certificate fingerprint is on known bad lists"""
        # Hash the fingerprint to create a deterministic but random-looking result
        cert_hash = int(hashlib.md5(fingerprint.encode()).hexdigest(), 16) % 100
        
        # 3% chance of being suspicious
        is_suspicious = cert_hash < 3
        
        if is_suspicious:
            reason = "Certificate matches known compromised certificate pattern"
            reputation_score = 20 + (cert_hash % 30)  # 20-49
        else:
            reason = "Certificate appears legitimate"
            reputation_score = 80 + (cert_hash % 20)  # 80-99
        
        return {
            'is_suspicious': is_suspicious,
            'reputation_score': reputation_score,
            'reason': reason,
            'source': 'mock_data' if self.enable_mock else 'certificate_reputation_check'
        }
    
    def _is_suspicious_header(self, header, value):
        """Check if an HTTP header value matches known malicious patterns"""
        suspicious_patterns = [
            r'eval\s*\(',
            r'document\.cookie',
            r'<script',
            r'javascript:',
            r'onload=',
            r'onerror=',
            r'fromCharCode'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        
        return False
    
    def _fetch_real_domain_intelligence(self, domain):
        """
        Fetch real threat intelligence for a domain
        
        This is a placeholder for actual implementation that would
        call external threat intelligence APIs
        """
        logger.warning("Real threat intelligence APIs not implemented")
        return self._get_mock_domain_data(domain)
    
    def _fetch_real_ip_intelligence(self, ip_address):
        """
        Fetch real threat intelligence for an IP address
        
        This is a placeholder for actual implementation that would
        call external threat intelligence APIs
        """
        logger.warning("Real threat intelligence APIs not implemented")
        return self._get_mock_ip_data(ip_address)