# backend/scanner/services/scan_types.py

"""
This module defines all available scan types and their descriptions.
Used to maintain consistent scan type information across the application.
"""

# Dictionary of all supported scan types
SCAN_TYPES = {
    'headers': {
        'name': 'HTTP Headers Analysis',
        'description': 'Examines HTTP headers for missing security headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.',
        'icon': 'shield',
        'default_enabled': True,
        'category': 'web_security'
    },
    'ssl': {
        'name': 'SSL/TLS Configuration',
        'description': 'Checks SSL/TLS certificate validity, protocol versions, and cipher suites to identify potential vulnerabilities.',
        'icon': 'lock',
        'default_enabled': True,
        'category': 'web_security'
    },
    'vulnerabilities': {
        'name': 'Vulnerability Scan',
        'description': 'Detects common web vulnerabilities such as exposed sensitive files, outdated software versions, and security misconfigurations.',
        'icon': 'alert-triangle',
        'default_enabled': True,
        'category': 'web_security'
    },
    'content': {
        'name': 'Content Analysis',
        'description': 'Analyzes page content for SEO issues, accessibility problems, and potential information disclosure risks.',
        'icon': 'file-text',
        'default_enabled': False,
        'category': 'content_quality'
    },
    'ports': {
        'name': 'Port Scanning',
        'description': 'Identifies open ports and services that could potentially expose your infrastructure to attackers.',
        'icon': 'server',
        'default_enabled': False,
        'category': 'infrastructure'
    },
    'csp': {
        'name': 'Content Security Policy',
        'description': 'Evaluates your CSP implementation to ensure proper protection against cross-site scripting (XSS) and other code injection attacks.',
        'icon': 'shield',
        'default_enabled': True,
        'category': 'web_security'
    },
    'cookies': {
        'name': 'Cookie Security',
        'description': 'Analyzes cookies for security issues such as missing Secure and HttpOnly flags, inappropriate SameSite settings, and long expiration times.',
        'icon': 'cookie',
        'default_enabled': False,
        'category': 'web_security'
    },
    'cors': {
        'name': 'CORS Configuration',
        'description': 'Checks Cross-Origin Resource Sharing settings to identify potential security vulnerabilities.',
        'icon': 'git-branch',
        'default_enabled': False,
        'category': 'web_security'
    },
    'server': {
        'name': 'Server Analysis',
        'description': 'Examines server configuration, information disclosure, and potential server-related vulnerabilities.',
        'icon': 'database',
        'default_enabled': False,
        'category': 'infrastructure'
    },
}

# Categories for grouping scan types
SCAN_CATEGORIES = {
    'web_security': {
        'name': 'Web Security',
        'description': 'Scans related to web application security',
        'icon': 'shield'
    },
    'infrastructure': {
        'name': 'Infrastructure',
        'description': 'Scans related to server and network infrastructure',
        'icon': 'server'
    },
    'content_quality': {
        'name': 'Content Quality',
        'description': 'Scans related to website content and SEO',
        'icon': 'file-text'
    }
}

def get_scan_types():
    """
    Returns all available scan types
    """
    return SCAN_TYPES

def get_scan_categories():
    """
    Returns all scan categories
    """
    return SCAN_CATEGORIES

def get_default_scan_types():
    """
    Returns a list of scan type keys that are enabled by default
    """
    return [key for key, info in SCAN_TYPES.items() if info.get('default_enabled', False)]