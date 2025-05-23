# backend/scanner/services/ssl_scanner.py

import socket
import ssl
import logging
from urllib.parse import urlparse
import datetime

logger = logging.getLogger(__name__)

class SslScanner:
    """Scanner for SSL/TLS configuration"""
    
    def __init__(self, url):
        self.url = url
        parsed_url = urlparse(url)
        self.hostname = parsed_url.netloc.split(':')[0]
        self.port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
    def scan(self):
        """Scan the target URL for SSL/TLS configuration issues"""
        findings = []
        
        # Skip if not HTTPS
        if urlparse(self.url).scheme != 'https':
            findings.append({
                'name': 'Not Using HTTPS',
                'description': f'The website {self.url} is not using HTTPS, which is insecure for transmitting sensitive information.',
                'severity': 'high',
                'details': {
                    'recommendation': 'Enable HTTPS for secure communication.',
                    'current_scheme': urlparse(self.url).scheme
                }
            })
            return findings
        
        try:
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate validity
                    findings.extend(self._check_certificate_validity(cert))
                    
                    # Check protocol version
                    findings.extend(self._check_protocol_version(ssock.version()))
                    
                    # Check cipher strength
                    findings.extend(self._check_cipher_strength(cipher))
        
        except (socket.error, ssl.SSLError, TimeoutError) as e:
            logger.error(f"Error in SSL scan for {self.url}: {str(e)}")
            findings.append({
                'name': 'SSL Connection Error',
                'description': f'Failed to establish SSL connection to {self.url}: {str(e)}',
                'severity': 'info',
                'details': {'error': str(e)}
            })
        
        return findings
    
    def _check_certificate_validity(self, cert):
        findings = []
        
        # Check expiration date
        not_after = ssl.cert_time_to_seconds(cert['notAfter'])
        not_after_date = datetime.datetime.fromtimestamp(not_after)
        days_until_expiry = (not_after_date - datetime.datetime.now()).days
        
        if days_until_expiry <= 0:
            findings.append({
                'name': 'SSL Certificate Expired',
                'description': f'The SSL certificate for {self.hostname} has expired on {cert["notAfter"]}.',
                'severity': 'critical',
                'details': {
                    'expiry_date': cert['notAfter'],
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
                    'recommendation': 'Renew the SSL certificate before it expires.'
                }
            })
        
        # Check if certificate is for correct domain
        if 'subjectAltName' in cert:
            san_names = [name for t, name in cert['subjectAltName'] if t == 'DNS']
            if self.hostname not in san_names:
                findings.append({
                    'name': 'SSL Certificate Domain Mismatch',
                    'description': f'The SSL certificate is not valid for {self.hostname}.',
                    'severity': 'high',
                    'details': {
                        'hostname': self.hostname,
                        'certificate_domains': san_names,
                        'recommendation': 'Obtain a certificate valid for this domain.'
                    }
                })
        
        return findings
    
    def _check_protocol_version(self, version):
        findings = []
        
        # Check for outdated SSL/TLS versions
        if version == 'SSLv3' or version == 'TLSv1' or version == 'TLSv1.1':
            findings.append({
                'name': 'Outdated SSL/TLS Protocol',
                'description': f'The server is using an outdated SSL/TLS protocol: {version}.',
                'severity': 'high',
                'details': {
                    'current_protocol': version,
                    'recommendation': 'Configure the server to use TLSv1.2 or TLSv1.3 only.'
                }
            })
        
        return findings
    
    def _check_cipher_strength(self, cipher):
        findings = []
        
        # Check for weak ciphers
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
        cipher_name = cipher[0]
        
        for weak in weak_ciphers:
            if weak in cipher_name:
                findings.append({
                    'name': 'Weak Cipher Suite',
                    'description': f'The server is using a weak cipher suite: {cipher_name}.',
                    'severity': 'high',
                    'details': {
                        'cipher_suite': cipher_name,
                        'recommendation': 'Configure the server to use strong cipher suites only.'
                    }
                })
                break
        
        return findings