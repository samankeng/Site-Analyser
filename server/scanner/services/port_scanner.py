# backend/scanner/services/port_scanner.py

import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class PortScanner:
    """Scanner for open ports and services with detailed findings"""
    
    def __init__(self, url):
        self.url = url
        parsed_url = urlparse(url)
        self.hostname = parsed_url.netloc.split(':')[0]
        
        # Common ports to scan with descriptions
        self.common_ports = [
            {'port': 21, 'name': 'FTP', 'description': 'File Transfer Protocol - Used for file uploads/downloads'},
            {'port': 22, 'name': 'SSH', 'description': 'Secure Shell - Remote server administration'},
            {'port': 23, 'name': 'Telnet', 'description': 'Unencrypted remote access (insecure)'},
            {'port': 25, 'name': 'SMTP', 'description': 'Simple Mail Transfer Protocol - Email sending'},
            {'port': 53, 'name': 'DNS', 'description': 'Domain Name System - Name resolution'},
            {'port': 80, 'name': 'HTTP', 'description': 'Unencrypted web traffic'},
            {'port': 110, 'name': 'POP3', 'description': 'Post Office Protocol - Email retrieval'},
            {'port': 135, 'name': 'MSRPC', 'description': 'Microsoft Remote Procedure Call'},
            {'port': 139, 'name': 'NetBIOS', 'description': 'Network Basic Input/Output System'},
            {'port': 143, 'name': 'IMAP', 'description': 'Internet Message Access Protocol - Email retrieval'},
            {'port': 443, 'name': 'HTTPS', 'description': 'Encrypted web traffic'},
            {'port': 445, 'name': 'SMB', 'description': 'Server Message Block - File sharing'},
            {'port': 993, 'name': 'IMAPS', 'description': 'Secure IMAP - Encrypted email retrieval'},
            {'port': 995, 'name': 'POP3S', 'description': 'Secure POP3 - Encrypted email retrieval'},
            {'port': 1723, 'name': 'PPTP', 'description': 'Point-to-Point Tunneling Protocol - VPN service'},
            {'port': 3306, 'name': 'MySQL', 'description': 'MySQL database service'},
            {'port': 3389, 'name': 'RDP', 'description': 'Remote Desktop Protocol - Remote access'},
            {'port': 5900, 'name': 'VNC', 'description': 'Virtual Network Computing - Remote desktop access'},
            {'port': 8080, 'name': 'HTTP-ALT', 'description': 'Alternative HTTP port, often used for proxies'},
            {'port': 8443, 'name': 'HTTPS-ALT', 'description': 'Alternative HTTPS port'}
        ]
        
        # Risk levels for ports
        self.risky_ports = {
            21: {'risk': 'high', 'reason': 'FTP often transmits credentials in cleartext'},
            23: {'risk': 'critical', 'reason': 'Telnet transmits all data including passwords in cleartext'},
            25: {'risk': 'medium', 'reason': 'SMTP can be abused for spam relay if misconfigured'},
            135: {'risk': 'high', 'reason': 'MSRPC has many known vulnerabilities and is often targeted'},
            139: {'risk': 'high', 'reason': 'NetBIOS is frequently exploited in Windows environments'},
            445: {'risk': 'high', 'reason': 'SMB has been the target of many critical exploits (EternalBlue, etc.)'},
            1433: {'risk': 'high', 'reason': 'MS SQL should not be exposed to the internet'},
            1521: {'risk': 'high', 'reason': 'Oracle DB should not be exposed to the internet'},
            3306: {'risk': 'medium', 'reason': 'MySQL should generally not be exposed to the internet'},
            3389: {'risk': 'high', 'reason': 'RDP is frequently targeted by brute force attacks'},
            5900: {'risk': 'high', 'reason': 'VNC is often unencrypted and targeted for unauthorized access'}
        }
    
    def scan(self):
        """Scan the target for open ports with enhanced details"""
        findings = []
        
        try:
            # Get list of open ports using Python sockets
            open_ports = self._scan_ports()
            
            if not open_ports:
                findings.append({
                    'name': 'No Open Ports Detected',
                    'description': f'No commonly used ports were found open on {self.hostname}.',
                    'severity': 'info',
                    'details': {
                        'hostname': self.hostname,
                        'ports_scanned': [p['port'] for p in self.common_ports],
                        'impact': 'Limited attack surface due to minimal exposed services.',
                        'recommendation': 'Continue to monitor and maintain good security practices.'
                    }
                })
                return findings
            
            # Create a detailed finding for all open ports with specific information
            port_details = []
            risky_port_details = []
            
            for port_info in open_ports:
                port_num = port_info['port']
                service = port_info['service']
                
                # Find the port description
                port_desc = next((p['description'] for p in self.common_ports if p['port'] == port_num), 'Unknown service')
                
                # Determine if this is a risky port
                is_risky = port_num in self.risky_ports
                risk_info = self.risky_ports.get(port_num, {'risk': 'low', 'reason': 'No specific risk'})
                
                port_entry = {
                    'port': port_num,
                    'service': service,
                    'description': port_desc,
                    'risk_level': risk_info['risk'] if is_risky else 'low',
                    'risk_reason': risk_info['reason'] if is_risky else 'No specific risk'
                }
                
                port_details.append(port_entry)
                if is_risky:
                    risky_port_details.append(port_entry)
            
            # Add a general finding about open ports
            port_list_text = ", ".join([f"{p['port']}/{p['service']}" for p in open_ports])
            findings.append({
                'name': 'Open Ports Detected',
                'description': f'Found {len(open_ports)} open ports on {self.hostname}: {port_list_text}',
                'severity': 'info',
                'details': {
                    'hostname': self.hostname,
                    'open_ports': port_details,
                    'page_url': self.url,
                    'ports_list': port_list_text,
                    'impact': 'Each open port potentially increases the attack surface of the server.',
                    'recommendation': 'Review each service and close unnecessary ports.'
                }
            })
            
            # Add specific findings for risky ports
            if risky_port_details:
                # Determine highest risk level
                highest_risk = max([p['risk_level'] for p in risky_port_details], key=lambda x: 
                                 {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(x, 0))
                
                # Convert to appropriate severity
                severity_map = {'low': 'low', 'medium': 'medium', 'high': 'high', 'critical': 'critical'}
                severity = severity_map.get(highest_risk, 'medium')
                
                # Create a list of risky ports to display
                risky_port_list = ", ".join([f"{p['port']}/{p['service']} ({p['risk_level']})" for p in risky_port_details])
                
                findings.append({
                    'name': 'Potentially Risky Open Ports',
                    'description': f'Found {len(risky_port_details)} potentially risky open ports on {self.hostname}: {risky_port_list}',
                    'severity': severity,
                    'details': {
                        'hostname': self.hostname,
                        'risky_ports': risky_port_details,
                        'page_url': self.url,
                        'impact': 'These ports may expose vulnerable services that could be exploited by attackers.',
                        'recommendation': 'Review each service carefully. If possible, close these ports or restrict access with a firewall.'
                    }
                })
                
                # Add individual findings for the most critical ports
                for port_entry in risky_port_details:
                    if port_entry['risk_level'] in ['high', 'critical']:
                        findings.append({
                            'name': f'Exposed {port_entry["service"]} Service (Port {port_entry["port"]})',
                            'description': f'Port {port_entry["port"]} ({port_entry["service"]}) is open: {port_entry["risk_reason"]}',
                            'severity': severity_map.get(port_entry['risk_level'], 'medium'),
                            'details': {
                                'hostname': self.hostname,
                                'port': port_entry['port'],
                                'service': port_entry['service'],
                                'description': port_entry['description'],
                                'page_url': self.url,
                                'impact': port_entry['risk_reason'],
                                'recommendation': f'If not required, close port {port_entry["port"]} or restrict access with a firewall.'
                            }
                        })
            
        except Exception as e:
            logger.error(f"Error in port scan for {self.url}: {str(e)}")
            findings.append({
                'name': 'Port Scan Error',
                'description': f'Error scanning ports on {self.hostname}: {str(e)}',
                'severity': 'info',
                'details': {
                    'error': str(e),
                    'hostname': self.hostname,
                    'url': self.url
                }
            })
        
        return findings
    
    def _scan_ports(self):
        """Scan common ports using Python socket"""
        open_ports = []
        
        for port_item in self.common_ports:
            port = port_item['port']
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)  # 1 second timeout
                
                # Try to connect
                result = s.connect_ex((self.hostname, port))
                
                # If the connection was successful (port is open)
                if result == 0:
                    try:
                        # Try to get service name
                        service = socket.getservbyport(port)
                    except (OSError, socket.error):
                        service = port_item['name'] if 'name' in port_item else "unknown"
                    
                    open_ports.append({
                        'port': port,
                        'service': service
                    })
                
                s.close()
                
            except socket.gaierror:
                logger.error(f"Hostname {self.hostname} could not be resolved")
                break
            except socket.error as e:
                logger.error(f"Socket error scanning port {port}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error scanning port {port}: {str(e)}")
        
        return open_ports