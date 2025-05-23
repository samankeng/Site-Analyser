# backend/scanner/services/csp_scanner.py

import logging
import requests
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class CspScanner:
    """Content Security Policy scanner to evaluate CSP implementation"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            'User-Agent': 'SiteAnalyser-SecurityScanner/1.0'
        }
    
    def scan(self):
        """Scan the target URL for CSP headers and evaluate their strength"""
        findings = []
        
        try:
            # Get the headers from the target URL
            response = requests.get(self.target_url, headers=self.headers, timeout=10, verify=True)
            headers = response.headers
            
            # Check for CSP header
            csp_header = headers.get('Content-Security-Policy')
            csp_report_only = headers.get('Content-Security-Policy-Report-Only')
            
            # No CSP header found
            if not csp_header and not csp_report_only:
                findings.append({
                    'name': 'Missing Content Security Policy',
                    'description': 'No Content Security Policy header was found. CSP helps prevent XSS attacks by controlling which resources can be loaded.',
                    'severity': 'high',
                    'details': {
                        'recommendation': 'Implement a Content Security Policy header to restrict which resources can be loaded by the browser.'
                    }
                })
            else:
                # Analyze CSP if present
                csp_to_analyze = csp_header if csp_header else csp_report_only
                csp_findings = self._analyze_csp(csp_to_analyze, bool(csp_report_only))
                findings.extend(csp_findings)
                
            return findings
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error connecting to {self.target_url}: {str(e)}")
            findings.append({
                'name': 'Connection Error',
                'description': f"Failed to connect to {self.target_url} to analyze CSP headers: {str(e)}",
                'severity': 'info',
                'details': {'error': str(e)}
            })
            return findings
    
    def _analyze_csp(self, csp_header, is_report_only=False):
        """Analyze the CSP header for common issues"""
        findings = []
        
        # Check if CSP is in report-only mode
        if is_report_only:
            findings.append({
                'name': 'CSP in Report-Only Mode',
                'description': 'Content Security Policy is set to report-only mode. This means violations are reported but not enforced.',
                'severity': 'medium',
                'details': {
                    'header': 'Content-Security-Policy-Report-Only',
                    'value': csp_header,
                    'recommendation': 'Once you have verified your CSP does not break functionality, switch to enforcement mode with Content-Security-Policy header.'
                }
            })
        
        # Parse CSP directives
        directives = self._parse_csp_directives(csp_header)
        
        # Check for unsafe directives
        if self._has_unsafe_inline(directives):
            findings.append({
                'name': 'Unsafe Inline Scripts/Styles Allowed',
                'description': 'The CSP allows unsafe-inline in script-src or style-src, which negates XSS protections.',
                'severity': 'high',
                'details': {
                    'value': csp_header,
                    'recommendation': 'Remove unsafe-inline from script-src and style-src directives. Use nonces or hashes instead.'
                }
            })
        
        if self._has_unsafe_eval(directives):
            findings.append({
                'name': 'Unsafe Eval Allowed',
                'description': 'The CSP allows unsafe-eval, which permits potentially dangerous runtime code evaluation.',
                'severity': 'medium',
                'details': {
                    'value': csp_header,
                    'recommendation': 'Remove unsafe-eval from script-src directive. Refactor code to avoid using eval() and similar functions.'
                }
            })
        
        # Check for wildcard sources
        if self._has_wildcard_sources(directives):
            findings.append({
                'name': 'Wildcard Sources in CSP',
                'description': 'The CSP contains wildcard (*) sources, which reduces its effectiveness.',
                'severity': 'medium',
                'details': {
                    'value': csp_header,
                    'recommendation': 'Replace * with specific domains where possible to limit the scope of allowed resources.'
                }
            })
        
        # Check for missing directives
        missing_directives = self._check_missing_directives(directives)
        if missing_directives:
            findings.append({
                'name': 'Missing Important CSP Directives',
                'description': f"The CSP is missing these recommended directives: {', '.join(missing_directives)}",
                'severity': 'medium',
                'details': {
                    'missing_directives': missing_directives,
                    'recommendation': 'Add these directives to strengthen your Content Security Policy.'
                }
            })
        
        # If no issues found and not in report-only mode, add a positive finding
        if not findings and not is_report_only:
            findings.append({
                'name': 'Strong Content Security Policy',
                'description': 'A well-configured Content Security Policy is in place.',
                'severity': 'info',
                'details': {
                    'value': csp_header
                }
            })
            
        return findings
    
    def _parse_csp_directives(self, csp_header):
        """Parse CSP header into a dictionary of directives"""
        directives = {}
        
        # Split the header by semicolons
        parts = csp_header.split(';')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            # Split each part into directive name and values
            fragments = part.split(' ')
            directive_name = fragments[0].lower()
            directive_values = fragments[1:] if len(fragments) > 1 else []
            
            directives[directive_name] = directive_values
            
        return directives
    
    def _has_unsafe_inline(self, directives):
        """Check if CSP allows unsafe-inline in script-src or style-src"""
        for directive in ['script-src', 'style-src', 'script-src-elem', 'style-src-elem']:
            if directive in directives and 'unsafe-inline' in directives[directive]:
                return True
        return False
    
    def _has_unsafe_eval(self, directives):
        """Check if CSP allows unsafe-eval in script-src"""
        for directive in ['script-src', 'script-src-elem']:
            if directive in directives and 'unsafe-eval' in directives[directive]:
                return True
        return False
    
    def _has_wildcard_sources(self, directives):
        """Check if CSP has wildcard (*) sources"""
        for directive, values in directives.items():
            # Skip report-uri and similar directives that might legitimately have a *
            if directive in ['report-uri', 'report-to']:
                continue
                
            if '*' in values:
                return True
        return False
    
    def _check_missing_directives(self, directives):
        """Check for important missing directives"""
        important_directives = [
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'connect-src',
            'frame-src',
            'font-src',
            'object-src',
            'base-uri'
        ]
        
        missing = []
        for directive in important_directives:
            # If default-src is present, it's a fallback for some directives
            if directive not in directives and (directive == 'default-src' or 'default-src' not in directives):
                missing.append(directive)
                
        return missing