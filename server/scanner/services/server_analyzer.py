# backend/scanner/services/server_analyzer.py

import requests
import logging
import re
from urllib.parse import urlparse
import socket
import ssl
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class ServerAnalyzer:
    """Scanner for server configuration and information leakage"""
    
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Site-Analyser Security Scanner/1.0'
        }
        parsed_url = urlparse(url)
        self.hostname = parsed_url.netloc.split(':')[0]
        self.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    
    def scan(self):
        """Scan for server information and configuration issues"""
        findings = []
        
        try:
            # Make a request to the target URL
            response = requests.get(self.url, headers=self.headers, timeout=10)
            
            # Check HTTP response headers
            header_findings = self._check_server_headers(response.headers)
            findings.extend(header_findings)
            
            # Check HTML content for server information
            html_findings = self._check_html_comments(response.text)
            findings.extend(html_findings)
            
            # Check DNS records
            dns_findings = self._check_dns_records()
            findings.extend(dns_findings)
            
            # Check TLS/SSL configuration
            if urlparse(self.url).scheme == 'https':
                ssl_findings = self._check_ssl_configuration()
                findings.extend(ssl_findings)
            
            # Check for server software version detection
            version_findings = self._detect_server_version(response.headers, response.text)
            findings.extend(version_findings)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error analyzing server for {self.url}: {str(e)}")
            findings.append({
                'name': 'Server Analysis Connection Error',
                'description': f'Failed to connect to {self.url} for server analysis: {str(e)}',
                'severity': 'info',
                'details': {
                    'error': str(e),
                    'hostname': self.hostname,
                    'page_url': self.url
                }
            })
        
        return findings
    
    def _check_server_headers(self, headers):
        """Analyze server headers for information disclosure"""
        findings = []
        
        # Check for server header
        server_header = headers.get('Server')
        if server_header:
            findings.append({
                'name': 'Server Header Information Disclosure',
                'description': f'The Server header is revealing detailed information: {server_header}',
                'severity': 'low',
                'details': {
                    'header_name': 'Server',
                    'header_value': server_header,
                    'page_url': self.url,
                    'impact': 'The Server header discloses information about the web server software and version, which can help attackers target known vulnerabilities.',
                    'recommendation': 'Configure the web server to remove or minimize information in the Server header.'
                }
            })
        
        # Check for X-Powered-By header
        powered_by = headers.get('X-Powered-By')
        if powered_by:
            findings.append({
                'name': 'X-Powered-By Information Disclosure',
                'description': f'The X-Powered-By header is revealing detailed information: {powered_by}',
                'severity': 'low',
                'details': {
                    'header_name': 'X-Powered-By',
                    'header_value': powered_by,
                    'page_url': self.url,
                    'impact': 'The X-Powered-By header discloses information about the technology stack, which can help attackers target known vulnerabilities.',
                    'recommendation': 'Configure the application to remove the X-Powered-By header.'
                }
            })
        
        # Check for other information-leaking headers
        info_headers = [
            'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache', 
            'X-Varnish', 'X-Drupal-Dynamic-Cache', 'X-Version', 'CF-Ray', 'X-Runtime',
            'X-Served-By', 'X-Amz-Cf-Id', 'X-Request-Id', 'X-Environment'
        ]
        
        for header in info_headers:
            if header in headers:
                findings.append({
                    'name': f'{header} Information Disclosure',
                    'description': f'The {header} header is revealing information: {headers[header]}',
                    'severity': 'low',
                    'details': {
                        'header_name': header,
                        'header_value': headers[header],
                        'page_url': self.url,
                        'impact': f'The {header} header discloses information about the technology stack or configuration, which can help attackers.',
                        'recommendation': f'Configure the application to remove the {header} header.'
                    }
                })
        
        # Check for missing security headers
        security_headers = {
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-XSS-Protection': 'Helps prevent XSS attacks in older browsers',
            'Content-Security-Policy': 'Prevents various attacks including XSS',
            'Strict-Transport-Security': 'Enforces HTTPS connections',
            'Referrer-Policy': 'Controls referrer information sent with requests',
            'Permissions-Policy': 'Controls browser feature permissions'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                findings.append({
                    'name': f'Missing {header} Header',
                    'description': f'The {header} header is missing, which {description}.',
                    'severity': 'low',
                    'details': {
                        'missing_header': header,
                        'description': description,
                        'page_url': self.url,
                        'impact': f'Without the {header} header, the site may be vulnerable to certain types of attacks.',
                        'recommendation': f'Implement the {header} header with appropriate values.'
                    }
                })
        
        return findings
    
    def _check_html_comments(self, html_content):
        """Check HTML comments for information disclosure"""
        findings = []
        
        # Parse HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        
        # Patterns to look for in comments
        sensitive_patterns = [
            (r'version', 'Version Information'),
            (r'todo', 'TODO Comment'),
            (r'fixme', 'FIXME Comment'),
            (r'bug', 'Bug Reference'),
            (r'user', 'User Information'),
            (r'pass', 'Password Reference'),
            (r'key', 'Key Reference'),
            (r'token', 'Token Reference'),
            (r'secret', 'Secret Reference'),
            (r'api', 'API Reference'),
            (r'database', 'Database Reference'),
            (r'config', 'Configuration Reference'),
            (r'(?:v\d+\.\d+\.\d+)', 'Version Number'),
            (r'(?:release\s+\d+\.\d+)', 'Release Number')
        ]
        
        sensitive_comments = []
        
        for comment in comments:
            comment_text = comment.strip()
            
            # Skip empty or minimal comments
            if len(comment_text) <= 10:
                continue
                
            # Check for sensitive information in comment
            for pattern, pattern_name in sensitive_patterns:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    # Truncate and sanitize comment for display
                    sanitized_comment = comment_text[:100] + ('...' if len(comment_text) > 100 else '')
                    sanitized_comment = sanitized_comment.replace('-->', '')
                    
                    sensitive_comments.append({
                        'pattern': pattern_name,
                        'comment': sanitized_comment
                    })
                    break  # Only report once per comment
        
        if sensitive_comments:
            findings.append({
                'name': 'Sensitive Information in HTML Comments',
                'description': f'Found {len(sensitive_comments)} HTML comments containing potentially sensitive information.',
                'severity': 'medium',
                'details': {
                    'sensitive_comments': sensitive_comments,
                    'page_url': self.url,
                    'impact': 'HTML comments may reveal sensitive information about the application structure, technology, or configuration.',
                    'recommendation': 'Remove sensitive information from HTML comments in production code.'
                }
            })
        
        return findings
    
    def _check_dns_records(self):
        """Check DNS records for information disclosure"""
        findings = []
        
        try:
            # Get IP address(es)
            ip_addresses = socket.gethostbyname_ex(self.hostname)[2]
            
            # Check if multiple IP addresses (possible load balancing)
            if len(ip_addresses) > 1:
                findings.append({
                    'name': 'Multiple IP Addresses Detected',
                    'description': f'The hostname {self.hostname} resolves to multiple IP addresses, suggesting load balancing.',
                    'severity': 'info',
                    'details': {
                        'hostname': self.hostname,
                        'ip_addresses': ip_addresses,
                        'page_url': self.url,
                        'impact': 'Load balancing information can be useful for understanding the infrastructure.',
                        'recommendation': 'This is informational and not necessarily a security issue.'
                    }
                })
            
            # Check if internal IP addresses are exposed
            internal_ips = [ip for ip in ip_addresses if self._is_internal_ip(ip)]
            if internal_ips:
                findings.append({
                    'name': 'Internal IP Addresses Exposed',
                    'description': f'The hostname {self.hostname} resolves to internal IP addresses.',
                    'severity': 'medium',
                    'details': {
                        'hostname': self.hostname,
                        'internal_ips': internal_ips,
                        'page_url': self.url,
                        'impact': 'Exposing internal IP addresses may reveal information about the internal network structure.',
                        'recommendation': 'Configure DNS to avoid exposing internal IP addresses publicly.'
                    }
                })
                
        except (socket.gaierror, socket.herror) as e:
            logger.error(f"Error checking DNS for {self.hostname}: {str(e)}")
        
        return findings
    
    def _is_internal_ip(self, ip):
        """Check if an IP address is internal/private"""
        # Check for private IP ranges
        octets = ip.split('.')
        if len(octets) != 4:
            return False
            
        # Check for 10.x.x.x
        if octets[0] == '10':
            return True
            
        # Check for 172.16.x.x through 172.31.x.x
        if octets[0] == '172' and 16 <= int(octets[1]) <= 31:
            return True
            
        # Check for 192.168.x.x
        if octets[0] == '192' and octets[1] == '168':
            return True
        
        # Check for localhost
        if ip == '127.0.0.1':
            return True
            
        return False
    
    def _check_ssl_configuration(self):
        """Check for SSL/TLS configuration details"""
        findings = []
        
        try:
            # Establish SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Get certificate details
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Check for self-signed certificate
                    if self._is_self_signed_cert(cert):
                        findings.append({
                            'name': 'Self-Signed Certificate',
                            'description': f'The server is using a self-signed certificate.',
                            'severity': 'medium',
                            'details': {
                                'hostname': self.hostname,
                                'certificate_subject': str(cert.get('subject', [])),
                                'certificate_issuer': str(cert.get('issuer', [])),
                                'page_url': self.url,
                                'impact': 'Self-signed certificates are not trusted by browsers and can lead to security warnings.',
                                'recommendation': 'Use certificates issued by trusted certification authorities.'
                            }
                        })
                    
                    # Check for suspicious issuers
                    issuer = self._get_organization_from_cert(cert, 'issuer')
                    if issuer and self._is_suspicious_issuer(issuer):
                        findings.append({
                            'name': 'Certificate from Suspicious Issuer',
                            'description': f'The SSL certificate is issued by a potentially suspicious issuer: {issuer}',
                            'severity': 'medium',
                            'details': {
                                'hostname': self.hostname,
                                'issuer': issuer,
                                'page_url': self.url,
                                'impact': 'Certificates from untrusted or suspicious issuers may indicate security risks.',
                                'recommendation': 'Use certificates from well-known, trusted certification authorities.'
                            }
                        })
                    
                    # Check for weak protocol versions
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append({
                            'name': 'Weak SSL/TLS Protocol',
                            'description': f'The server supports an outdated SSL/TLS protocol: {protocol}',
                            'severity': 'high',
                            'details': {
                                'hostname': self.hostname,
                                'protocol': protocol,
                                'page_url': self.url,
                                'impact': 'Outdated SSL/TLS protocols have known vulnerabilities that can be exploited.',
                                'recommendation': 'Configure the server to use only TLSv1.2 and TLSv1.3.'
                            }
                        })
                    
                    # Check for weak cipher suite
                    # Check for weak cipher suite
                    if cipher and self._is_weak_cipher(cipher[0]):
                        findings.append({
                            'name': 'Weak Cipher Suite',
                            'description': f'The server supports a weak cipher suite: {cipher[0]}',
                            'severity': 'medium',
                            'details': {
                                'hostname': self.hostname,
                                'cipher_suite': cipher[0],
                                'page_url': self.url,
                                'impact': 'Weak cipher suites can be vulnerable to various attacks.',
                                'recommendation': 'Configure the server to use only strong cipher suites.'
                            }
                        })
                    
                    # Check certificate expiration
                    expiry_issues = self._check_certificate_expiration(cert)
                    findings.extend(expiry_issues)
        
        except (socket.error, ssl.SSLError) as e:
            logger.error(f"Error checking SSL configuration for {self.hostname}: {str(e)}")
        
        return findings
    
    def _is_self_signed_cert(self, cert):
        """Check if the certificate is self-signed"""
        try:
            issuer = cert.get('issuer', ())
            subject = cert.get('subject', ())
            
            # Convert issuer and subject to dictionaries for easier comparison
            issuer_dict = {}
            subject_dict = {}
            
            def extract_cert_info(items):
                result = {}
                for item in items:
                    try:
                        if isinstance(item, tuple):
                            if len(item) >= 2:
                                key, value = item[0], item[1]
                                result[key] = value
                            elif len(item) == 1:
                                result[item[0]] = ''
                        elif isinstance(item, (str, int, float)):
                            result[str(item)] = ''
                    except Exception as e:
                        logger.warning(f"Error processing cert item {item}: {str(e)}")
                        continue
                return result
            
            issuer_dict = extract_cert_info(issuer)
            subject_dict = extract_cert_info(subject)
            
            # Check if issuer and subject are the same
            return issuer_dict == subject_dict
        except Exception as e:
            logger.error(f"Error checking self-signed certificate: {str(e)}")
            return False
    
    # def _get_organization_from_cert(self, cert, field='issuer'):
    #     """Extract organization name from certificate"""
    #     entries = cert.get(field, [])
    #     for key, value in entries:
    #         if key == 'organizationName':
    #             return value
    #     return None
    def _get_organization_from_cert(self, cert, field_name):
        """Extract organization information from certificate"""
        try:
            entries = cert.get(field_name, [])
            org_name = None
            
            for entry in entries:
                # Handle different entry formats
                if isinstance(entry, tuple):
                    if len(entry) >= 2:
                        key, value = entry[0], entry[1]
                        # Look for organization information
                        if key.lower() in ['o', 'ou', 'cn', 'organizationname', 'organization']:
                            org_name = value
                            break
                    elif len(entry) == 1:
                        # Single value entry - check if it contains org info
                        if isinstance(entry[0], str) and 'organization' in entry[0].lower():
                            org_name = entry[0]
                            break
                
            return org_name or "Unknown"
        except Exception as e:
            logger.error(f"Error extracting {field_name} from certificate: {str(e)}")
            return "Unknown"
    
    def _is_suspicious_issuer(self, issuer):
        """Check if an issuer name looks suspicious"""
        suspicious_keywords = [
            'test', 'local', 'internal', 'dev', 'development', 'staging', 
            'temporary', 'fake', 'invalid', 'localhost', 'self', 'dummy'
        ]
        
        return any(keyword in issuer.lower() for keyword in suspicious_keywords)
    
    def _is_weak_cipher(self, cipher_name):
        """Check if a cipher suite is considered weak"""
        weak_keywords = [
            'NULL', 'EXPORT', 'RC2', 'RC4', 'DES', '3DES', 'MD5', 'SHA1',
            'ANON', 'ADH', 'AECDH', 'IDEA'
        ]
        
        return any(keyword in cipher_name for keyword in weak_keywords)
    
    def _check_certificate_expiration(self, cert):
        """Check certificate expiration date"""
        findings = []
        
        import time
        from datetime import datetime, timedelta
        
        # Get expiration date
        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
        not_after_date = datetime.fromtimestamp(not_after)
        days_until_expiry = (not_after_date - datetime.now()).days
        
        if days_until_expiry <= 0:
            findings.append({
                'name': 'SSL Certificate Expired',
                'description': f'The SSL certificate for {self.hostname} has expired on {cert["notAfter"]}.',
                'severity': 'critical',
                'details': {
                    'expiry_date': cert['notAfter'],
                    'days_since_expiry': abs(days_until_expiry),
                    'page_url': self.url,
                    'impact': 'Expired certificates will trigger security warnings in browsers and may prevent users from accessing the site.',
                    'recommendation': 'Renew the SSL certificate immediately.'
                }
            })
        elif days_until_expiry <= 30:
            findings.append({
                'name': 'SSL Certificate Expiring Soon',
                'description': f'The SSL certificate for {self.hostname} will expire in {days_until_expiry} days.',
                'severity': 'medium',
                'details': {
                    'expiry_date': cert['notAfter'],
                    'days_until_expiry': days_until_expiry,
                    'page_url': self.url,
                    'impact': 'Certificates that expire soon will trigger security warnings if not renewed in time.',
                    'recommendation': 'Renew the SSL certificate before it expires.'
                }
            })
        
        return findings
    
    def _detect_server_version(self, headers, html_content):
        """Detect server software and version from headers and content"""
        findings = []
        
        # Common server signatures and their regex patterns
        server_patterns = [
            {
                'name': 'Apache',
                'pattern': r'Apache/([0-9.]+)',
                'header': 'Server',
                'known_vulnerabilities': {
                    '2.2': 'Apache 2.2.x has reached end of life and has multiple known vulnerabilities.',
                    '2.4.0': 'Multiple vulnerabilities in early Apache 2.4 versions.'
                }
            },
            {
                'name': 'Nginx',
                'pattern': r'nginx/([0-9.]+)',
                'header': 'Server',
                'known_vulnerabilities': {
                    '1.16': 'Older versions may have security vulnerabilities.',
                    '1.14': 'Multiple vulnerabilities fixed in newer versions.'
                }
            },
            {
                'name': 'IIS',
                'pattern': r'Microsoft-IIS/([0-9.]+)',
                'header': 'Server',
                'known_vulnerabilities': {
                    '7.5': 'IIS 7.5 has reached end of support.',
                    '7.0': 'IIS 7.0 has multiple known vulnerabilities.',
                    '6.0': 'IIS 6.0 has reached end of life and has critical vulnerabilities.'
                }
            },
            {
                'name': 'PHP',
                'pattern': r'PHP/([0-9.]+)',
                'header': 'X-Powered-By',
                'known_vulnerabilities': {
                    '5.': 'PHP 5.x has reached end of life and has many known vulnerabilities.',
                    '7.0': 'PHP 7.0.x has reached end of life.',
                    '7.1': 'PHP 7.1.x has reached end of life.',
                    '7.2': 'PHP 7.2.x has reached end of life.'
                }
            }
        ]
        
        # Check headers for server information
        for server in server_patterns:
            header_value = headers.get(server['header'], '')
            match = re.search(server['pattern'], header_value)
            
            if match:
                version = match.group(1)
                
                # Check for known vulnerable versions
                is_vulnerable = False
                vulnerability_description = None
                
                for vulnerable_version, description in server['known_vulnerabilities'].items():
                    if version.startswith(vulnerable_version):
                        is_vulnerable = True
                        vulnerability_description = description
                        break
                
                severity = 'medium' if is_vulnerable else 'low'
                
                findings.append({
                    'name': f'{server["name"]} Version Disclosed',
                    'description': f'The server is disclosing {server["name"]} version {version} in the {server["header"]} header.',
                    'severity': severity,
                    'details': {
                        'server': server['name'],
                        'version': version,
                        'header': server['header'],
                        'is_vulnerable': is_vulnerable,
                        'vulnerability_description': vulnerability_description,
                        'page_url': self.url,
                        'impact': 'Disclosing server version information helps attackers identify vulnerable software versions.',
                        'recommendation': f'Configure {server["name"]} to hide version information in HTTP headers.'
                    }
                })
        
        # Look for common CMS patterns
        cms_patterns = [
            {
                'name': 'WordPress',
                'patterns': [
                    r'<meta name="generator" content="WordPress ([0-9.]+)"',
                    r'/wp-content/',
                    r'/wp-includes/'
                ]
            },
            {
                'name': 'Drupal',
                'patterns': [
                    r'<meta name="Generator" content="Drupal ([0-9.]+)"',
                    r'Drupal\.settings',
                    r'/sites/default/files/'
                ]
            },
            {
                'name': 'Joomla',
                'patterns': [
                    r'<meta name="generator" content="Joomla! ([0-9.]+)"',
                    r'/components/com_',
                    r'Joomla!'
                ]
            }
        ]
        
        for cms in cms_patterns:
            for pattern in cms['patterns']:
                match = re.search(pattern, html_content)
                if match:
                    version = match.group(1) if '([0-9.]+)' in pattern and match.groups() else 'Unknown'
                    
                    findings.append({
                        'name': f'{cms["name"]} CMS Detected',
                        'description': f'The website appears to be using {cms["name"]} {version if version != "Unknown" else ""}.',
                        'severity': 'low',
                        'details': {
                            'cms': cms['name'],
                            'version': version,
                            'detection_pattern': pattern,
                            'page_url': self.url,
                            'impact': 'CMS detection allows attackers to target known vulnerabilities in the platform.',
                            'recommendation': 'Hide CMS information and keep the CMS updated to the latest version.'
                        }
                    })
                    
                    # Only report once per CMS
                    break
        
        return findings