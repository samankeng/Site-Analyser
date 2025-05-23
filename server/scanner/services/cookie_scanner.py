# backend/scanner/services/cookie_scanner.py

import requests
import logging
from urllib.parse import urlparse
import http.cookiejar
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class CookieScanner:
    """Scanner for cookie security configuration"""
    
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0'
        }
    
    def scan(self):
        """Scan the target URL for cookie security issues"""
        findings = []
        
        try:
            # Create a session to handle cookies
            session = requests.Session()
            response = session.get(self.url, headers=self.headers, timeout=10)
            
            # Get all cookies from the session
            cookies = session.cookies
            
            if not cookies:
                findings.append({
                    'name': 'No Cookies Found',
                    'description': 'No cookies were set during the scan of this website.',
                    'severity': 'info',
                    'details': {
                        'url': self.url,
                        'recommendation': 'This is just informational. If your site uses authentication or session management, cookies might be expected.'
                    }
                })
                return findings
            
            # Check each cookie for security issues
            for cookie in cookies:
                cookie_findings = self._check_cookie_security(cookie)
                findings.extend(cookie_findings)
            
            # Check for cookie policies
            cookie_policy_findings = self._check_cookie_policies(response)
            findings.extend(cookie_policy_findings)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error scanning cookies for {self.url}: {str(e)}")
            findings.append({
                'name': 'Connection Error',
                'description': f'Failed to connect to {self.url} to analyze cookies: {str(e)}',
                'severity': 'info',
                'details': {
                    'error': str(e),
                    'page_url': self.url
                }
            })
        
        return findings
    
    def _check_cookie_security(self, cookie):
        """Check individual cookie for security issues"""
        findings = []
        
        # Create a dictionary with cookie details
        cookie_details = {
            'name': cookie.name,
            'domain': cookie.domain,
            'path': cookie.path,
            'expires': cookie.expires,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('httponly'),
            'samesite': self._get_samesite_attribute(cookie)
        }
        
        # Check for Secure flag on cookies
        if not cookie.secure:
            findings.append({
                'name': 'Cookie Missing Secure Flag',
                'description': f'The cookie "{cookie.name}" is missing the Secure flag, allowing transmission over unencrypted connections.',
                'severity': 'medium',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'page_url': self.url,
                    'impact': 'Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, making them vulnerable to interception.',
                    'recommendation': 'Set the Secure flag on all cookies to ensure they are only sent over HTTPS connections.'
                }
            })
        
        # Check for HttpOnly flag on cookies
        if not cookie.has_nonstandard_attr('httponly'):
            findings.append({
                'name': 'Cookie Missing HttpOnly Flag',
                'description': f'The cookie "{cookie.name}" is missing the HttpOnly flag, making it accessible to JavaScript.',
                'severity': 'medium',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'page_url': self.url,
                    'impact': 'Cookies without the HttpOnly flag can be accessed by JavaScript, which increases the risk of cross-site scripting (XSS) attacks.',
                    'recommendation': 'Set the HttpOnly flag on cookies that don\'t need to be accessed by JavaScript.'
                }
            })
        
        # Check for SameSite attribute
        samesite = self._get_samesite_attribute(cookie)
        if not samesite:
            findings.append({
                'name': 'Cookie Missing SameSite Attribute',
                'description': f'The cookie "{cookie.name}" is missing the SameSite attribute, which helps prevent CSRF attacks.',
                'severity': 'low',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'page_url': self.url,
                    'impact': 'Cookies without the SameSite attribute may be vulnerable to cross-site request forgery (CSRF) attacks.',
                    'recommendation': 'Set the SameSite attribute to "Lax" or "Strict" on cookies to prevent CSRF attacks.'
                }
            })
        elif samesite.lower() == 'none' and not cookie.secure:
            findings.append({
                'name': 'Cookie with SameSite=None Missing Secure Flag',
                'description': f'The cookie "{cookie.name}" has SameSite=None but is missing the Secure flag, which is required by modern browsers.',
                'severity': 'medium',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'page_url': self.url,
                    'impact': 'Modern browsers require cookies with SameSite=None to also have the Secure flag, otherwise they may be rejected.',
                    'recommendation': 'Add the Secure flag to all cookies that use SameSite=None.'
                }
            })
        
        # Check for session cookies with long expiration
        if self._is_session_cookie(cookie.name) and cookie.expires and self._is_long_expiration(cookie.expires):
            findings.append({
                'name': 'Session Cookie with Long Expiration',
                'description': f'The session cookie "{cookie.name}" has a long expiration time, which may pose a security risk.',
                'severity': 'low',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'expires_date': self._format_expiration_date(cookie.expires),
                    'page_url': self.url,
                    'impact': 'Session cookies with long expiration times increase the risk of session hijacking if the cookie is stolen.',
                    'recommendation': 'Set session cookies to expire after a reasonable amount of time (e.g., 2 hours) or use session-only cookies with no expiration.'
                }
            })
        
        # Check for cookies scoped to all subdomains with sensitive names
        if cookie.domain.startswith('.') and self._is_sensitive_cookie(cookie.name):
            findings.append({
                'name': 'Sensitive Cookie Scoped to All Subdomains',
                'description': f'The sensitive cookie "{cookie.name}" is scoped to all subdomains, which may pose a security risk.',
                'severity': 'medium',
                'details': {
                    'cookie_name': cookie.name,
                    'cookie_details': cookie_details,
                    'page_url': self.url,
                    'impact': 'Cookies scoped to all subdomains can be accessed by any subdomain, potentially allowing subdomain takeover attacks to steal sensitive cookies.',
                    'recommendation': 'Scope sensitive cookies to specific subdomains rather than all subdomains.'
                }
            })
        
        return findings
    
    def _get_samesite_attribute(self, cookie):
        """Get the SameSite attribute value from a cookie"""
        for attr in cookie._rest.keys():
            if attr.lower() == 'samesite':
                return cookie._rest[attr]
        return None
    
    def _is_session_cookie(self, cookie_name):
        """Check if a cookie is likely a session cookie based on name"""
        session_keywords = ['sess', 'session', 'auth', 'token', 'jwt', 'logged', 'user', 'id', 'sid', 'login']
        return any(keyword in cookie_name.lower() for keyword in session_keywords)
    
    def _is_sensitive_cookie(self, cookie_name):
        """Check if a cookie is likely sensitive based on name"""
        sensitive_keywords = ['sess', 'session', 'auth', 'token', 'jwt', 'secret', 'login', 'pass', 'admin', 'user', 'key', 'cred']
        return any(keyword in cookie_name.lower() for keyword in sensitive_keywords)
    
    def _is_long_expiration(self, expires):
        """Check if cookie expiration is more than 24 hours in the future"""
        if not expires:
            return False
        
        import time
        current_time = time.time()
        days = (expires - current_time) / (24 * 60 * 60)
        
        # More than 30 days
        return days > 30
    
    def _format_expiration_date(self, timestamp):
        """Format a timestamp into a readable date string"""
        if not timestamp:
            return "No expiration (session only)"
        
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def _check_cookie_policies(self, response):
        """Check for cookie policy headers and notifications"""
        findings = []
        
        # Check for Cookie Policy headers
        headers = response.headers
        if 'Set-Cookie' in headers and not any(h in headers for h in ['P3P', 'Cookie-Policy']):
            findings.append({
                'name': 'Missing Cookie Policy Headers',
                'description': 'The website sets cookies but does not provide cookie policy headers.',
                'severity': 'low',
                'details': {
                    'url': self.url,
                    'page_url': self.url,
                    'impact': 'Missing cookie policy headers may not properly inform users about cookie usage, potentially violating privacy regulations.',
                    'recommendation': 'Add appropriate Cookie Policy headers and ensure compliance with privacy regulations like GDPR and CCPA.'
                }
            })
        
        # Check for cookie consent mechanism by looking for common cookie consent libraries
        html_content = response.text
        consent_libraries = [
            'cookieconsent', 'gdpr-cookie', 'cookielaw', 'cookie-notice', 
            'cookie-consent', 'cookiebanner', 'cookie-alert',
            'cookie_law_info', 'cookie_notice', 'gdpr', 'cookiebot'
        ]
        
        has_consent_mechanism = any(lib in html_content.lower() for lib in consent_libraries)
        if not has_consent_mechanism and 'Set-Cookie' in headers:
            findings.append({
                'name': 'No Cookie Consent Mechanism Detected',
                'description': 'The website sets cookies but no cookie consent mechanism was detected.',
                'severity': 'low',
                'details': {
                    'url': self.url,
                    'page_url': self.url,
                    'impact': 'Websites that set cookies without obtaining user consent may violate privacy regulations like GDPR and CCPA.',
                    'recommendation': 'Implement a cookie consent mechanism that allows users to accept or reject non-essential cookies.'
                }
            })
        
        return findings