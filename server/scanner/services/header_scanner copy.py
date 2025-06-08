# backend/scanner/services/header_scanner.py

import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class HeaderScanner:
    """Scanner for HTTP security headers"""
    
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0'
        }
    
    def scan(self):
        """Scan the target URL for security headers"""
        try:
            findings = []
            
            # Make request to target URL
            response = requests.get(self.url, headers=self.headers, timeout=10, verify=True)
            headers = response.headers
            
            # Check for security headers
            findings.extend(self._check_content_security_policy(headers))
            findings.extend(self._check_strict_transport_security(headers))
            findings.extend(self._check_x_content_type_options(headers))
            findings.extend(self._check_x_frame_options(headers))
            findings.extend(self._check_referrer_policy(headers))
            findings.extend(self._check_permissions_policy(headers))
            
            return findings
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning headers for {self.url}: {str(e)}")
            return [{
                'name': 'Connection Error',
                'description': f'Failed to connect to {self.url}: {str(e)}',
                'severity': 'info',
                'details': {'error': str(e)}
            }]
    
    def _check_content_security_policy(self, headers):
        findings = []
        
        if 'Content-Security-Policy' not in headers:
            findings.append({
                'name': 'Missing Content-Security-Policy Header',
                'description': 'The Content-Security-Policy header is missing. This header helps prevent Cross-Site Scripting (XSS) and data injection attacks.',
                'severity': 'medium',
                'details': {
                    'recommendation': "Add a Content-Security-Policy header to restrict sources of content.",
                    'example': "Content-Security-Policy: default-src 'self'"
                }
            })
        
        return findings
    
    def _check_strict_transport_security(self, headers):
        findings = []
        
        # Check if site is HTTPS
        parsed_url = urlparse(self.url)
        if parsed_url.scheme == 'https':
            if 'Strict-Transport-Security' not in headers:
                findings.append({
                    'name': 'Missing Strict-Transport-Security Header',
                    'description': 'The HTTP Strict-Transport-Security header is missing. This header informs browsers to only use HTTPS, protecting against protocol downgrade attacks.',
                    'severity': 'medium',
                    'details': {
                        'recommendation': "Add a Strict-Transport-Security header for HTTPS enforcement.",
                        'example': "Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    }
                })
        
        return findings
    
    def _check_x_content_type_options(self, headers):
        findings = []
        
        if 'X-Content-Type-Options' not in headers:
            findings.append({
                'name': 'Missing X-Content-Type-Options Header',
                'description': 'The X-Content-Type-Options header is missing. This header prevents browsers from MIME-sniffing a response away from the declared content-type.',
                'severity': 'low',
                'details': {
                    'recommendation': "Add the X-Content-Type-Options header with value 'nosniff'.",
                    'example': "X-Content-Type-Options: nosniff"
                }
            })
        
        return findings
    
    def _check_x_frame_options(self, headers):
        findings = []
        
        if 'X-Frame-Options' not in headers:
            findings.append({
                'name': 'Missing X-Frame-Options Header',
                'description': 'The X-Frame-Options header is missing. This header protects against clickjacking attacks by preventing your page from being embedded in an iframe.',
                'severity': 'medium',
                'details': {
                    'recommendation': "Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'.",
                    'example': "X-Frame-Options: SAMEORIGIN"
                }
            })
        
        return findings
    
    def _check_referrer_policy(self, headers):
        findings = []
        
        if 'Referrer-Policy' not in headers:
            findings.append({
                'name': 'Missing Referrer-Policy Header',
                'description': 'The Referrer-Policy header is missing. This header controls how much referrer information should be included with requests.',
                'severity': 'low',
                'details': {
                    'recommendation': "Add a Referrer-Policy header to control referrer information.",
                    'example': "Referrer-Policy: strict-origin-when-cross-origin"
                }
            })
        
        return findings
    
    def _check_permissions_policy(self, headers):
        findings = []
        
        if 'Permissions-Policy' not in headers and 'Feature-Policy' not in headers:
            findings.append({
                'name': 'Missing Permissions-Policy Header',
                'description': 'The Permissions-Policy header is missing. This header allows a site to control which features and APIs can be used in the browser.',
                'severity': 'low',
                'details': {
                    'recommendation': "Add a Permissions-Policy header to control browser feature usage.",
                    'example': "Permissions-Policy: camera=(), microphone=(), geolocation=()"
                }
            })
        
        return findings