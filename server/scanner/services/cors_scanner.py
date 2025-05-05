# backend/scanner/services/cors_scanner.py

import requests
import logging
from urllib.parse import urlparse
import json

logger = logging.getLogger(__name__)

class CorsScanner:
    """Scanner for Cross-Origin Resource Sharing (CORS) configuration"""
    
    def __init__(self, url):
        self.url = url
        self.base_url = self._get_base_url(url)
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0',
            'Origin': 'https://security-scanner-test.com'  # Fake origin for testing CORS
        }
    
    def _get_base_url(self, url):
        """Extract the base URL (scheme + netloc)"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def scan(self):
        """Scan the target URL for CORS configuration issues"""
        findings = []
        
        try:
            # Test main URL
            main_findings = self._test_cors_configuration(self.url)
            findings.extend(main_findings)
            
            # Test common API endpoints
            api_endpoints = self._get_common_api_endpoints()
            for endpoint in api_endpoints:
                endpoint_url = f"{self.base_url}{endpoint}"
                endpoint_findings = self._test_cors_configuration(endpoint_url)
                findings.extend(endpoint_findings)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning CORS for {self.url}: {str(e)}")
            findings.append({
                'name': 'CORS Scan Connection Error',
                'description': f'Failed to connect to {self.url} to analyze CORS headers: {str(e)}',
                'severity': 'info',
                'details': {'error': str(e)}
            })
        
        return findings
    
    def _get_common_api_endpoints(self):
        """Return a list of common API endpoints to test"""
        return [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/api/users/',
            '/api/data/',
            '/api/auth/',
            '/api/login/',
            '/v1/',
            '/v2/',
            '/graphql',
            '/graphql/console',
            '/wp-json/',
            '/wp-json/wp/v2/',
            '/rest/',
            '/rest/v1/',
            '/service/',
            '/services/',
        ]
    
    def _test_cors_configuration(self, url):
        """Test a specific URL for CORS configuration issues"""
        findings = []
        
        try:
            # Make OPTIONS request to check preflight response
            options_response = requests.options(
                url, 
                headers=self.headers, 
                timeout=10
            )
            
            # Make GET request with Origin header to test CORS response
            get_response = requests.get(
                url, 
                headers=self.headers, 
                timeout=10
            )
            
            # Check CORS headers in the responses
            options_headers = options_response.headers
            get_headers = get_response.headers
            
            # Combine headers from both responses for analysis
            cors_headers = {
                'Access-Control-Allow-Origin': get_headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': get_headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': options_headers.get('Access-Control-Allow-Methods'),
                'Access-Control-Allow-Headers': options_headers.get('Access-Control-Allow-Headers'),
                'Access-Control-Expose-Headers': get_headers.get('Access-Control-Expose-Headers'),
                'Access-Control-Max-Age': options_headers.get('Access-Control-Max-Age')
            }
            
            # Remove None values
            cors_headers = {k: v for k, v in cors_headers.items() if v is not None}
            
            # If CORS is not implemented or disabled, there will be no CORS headers
            if not cors_headers:
                # This is not a finding, just information
                return []
            
            # Check for specific CORS issues
            if cors_headers.get('Access-Control-Allow-Origin') == '*':
                findings.append({
                    'name': 'CORS Wildcard Origin',
                    'description': f'The endpoint {url} allows CORS requests from any origin (*).',
                    'severity': 'medium',
                    'details': {
                        'url': url,
                        'headers': cors_headers,
                        'impact': 'Allowing CORS from any origin may expose sensitive information to untrusted domains if credentials are also allowed.',
                        'recommendation': 'Restrict CORS to specific trusted origins instead of using a wildcard (*).'
                    }
                })
            
            # Check if credentials are allowed with wildcard origin
            if (cors_headers.get('Access-Control-Allow-Origin') == '*' and
                cors_headers.get('Access-Control-Allow-Credentials') == 'true'):
                findings.append({
                    'name': 'CORS Credentials with Wildcard Origin',
                    'description': f'The endpoint {url} allows credentials with a wildcard origin, which is invalid and insecure.',
                    'severity': 'high',
                    'details': {
                        'url': url,
                        'headers': cors_headers,
                        'impact': 'This configuration is invalid. Browsers will reject this CORS configuration, breaking functionality.',
                        'recommendation': 'Specify exact origins instead of a wildcard when allowing credentials.'
                    }
                })
            
            # Check for overly permissive origins that might be exploitable
            origin_value = cors_headers.get('Access-Control-Allow-Origin', '')
            if origin_value and origin_value != '*' and self._is_exploitable_origin_pattern(origin_value):
                findings.append({
                    'name': 'CORS Origin Reflection',
                    'description': f'The endpoint {url} may be reflecting the Origin header in CORS response.',
                    'severity': 'high',
                    'details': {
                        'url': url,
                        'headers': cors_headers,
                        'reflected_origin': origin_value,
                        'test_origin': self.headers['Origin'],
                        'impact': 'Origin reflection can allow any website to make cross-origin requests, bypassing CORS protection.',
                        'recommendation': 'Implement a whitelist of allowed origins instead of reflecting the Origin header.'
                    }
                })
            
            # Check for overly permissive methods
            methods = cors_headers.get('Access-Control-Allow-Methods', '')
            if 'DELETE' in methods or 'PUT' in methods or methods == '*':
                findings.append({
                    'name': 'CORS Allows Dangerous Methods',
                    'description': f'The endpoint {url} allows potentially dangerous HTTP methods via CORS.',
                    'severity': 'medium',
                    'details': {
                        'url': url,
                        'allowed_methods': methods,
                        'impact': 'Allowing dangerous methods like DELETE or PUT can enable cross-origin attackers to modify server data.',
                        'recommendation': 'Restrict CORS methods to only those necessary (typically GET, POST).'
                    }
                })
            
        except requests.exceptions.RequestException:
            # Skip this endpoint if we can't connect
            pass
        
        return findings
    
    def _is_exploitable_origin_pattern(self, origin_value):
        """Check if an origin value indicates reflection or dangerous patterns"""
        # Check if our test origin is reflected (exact match)
        if origin_value == self.headers['Origin']:
            return True
        
        # Check for null origin (can be exploited in some cases)
        if origin_value.lower() == 'null':
            return True
        
        # Check for substring match (partial reflection)
        test_origin_domain = urlparse(self.headers['Origin']).netloc
        if test_origin_domain in origin_value:
            return True
        
        return False