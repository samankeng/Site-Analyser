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
            {'port': 80, 'name': 'HTTP', 'description': 'Standard web traffic port'},
            {'port': 110, 'name': 'POP3', 'description': 'Post Office Protocol - Email retrieval'},
            {'port': 135, 'name': 'MSRPC', 'description': 'Microsoft Remote Procedure Call'},
            {'port': 139, 'name': 'NetBIOS', 'description': 'Network Basic Input/Output System'},
            {'port': 143, 'name': 'IMAP', 'description': 'Internet Message Access Protocol - Email retrieval'},
            {'port': 443, 'name': 'HTTPS', 'description': 'Encrypted web traffic'},
            {'port': 445, 'name': 'SMB', 'description': 'Server Message Block - File sharing'},
            {'port': 993, 'name': 'IMAPS', 'description': 'Secure IMAP - Encrypted email retrieval'},
            {'port': 995, 'name': 'POP3S', 'description': 'Secure POP3 - Encrypted email retrieval'},
            {'port': 1433, 'name': 'MSSQL', 'description': 'Microsoft SQL Server database'},
            {'port': 1521, 'name': 'Oracle', 'description': 'Oracle database service'},
            {'port': 1723, 'name': 'PPTP', 'description': 'Point-to-Point Tunneling Protocol - VPN service'},
            {'port': 3306, 'name': 'MySQL', 'description': 'MySQL database service'},
            {'port': 3389, 'name': 'RDP', 'description': 'Remote Desktop Protocol - Remote access'},
            {'port': 5432, 'name': 'PostgreSQL', 'description': 'PostgreSQL database service'},
            {'port': 5900, 'name': 'VNC', 'description': 'Virtual Network Computing - Remote desktop access'},
            {'port': 8080, 'name': 'HTTP-ALT', 'description': 'Alternative HTTP port, often used for proxies'},
            {'port': 8443, 'name': 'HTTPS-ALT', 'description': 'Alternative HTTPS port'}
        ]
        
        # Standard web ports that are expected and secure
        self.standard_web_ports = {
            80: {
                'category': 'standard_web',
                'security_note': 'Standard HTTP port - ensure redirects to HTTPS for sensitive data',
                'recommendation': 'Verify HTTP redirects to HTTPS if handling sensitive information'
            },
            443: {
                'category': 'secure_web', 
                'security_note': 'Encrypted HTTPS port - this is secure and recommended',
                'recommendation': 'Continue using HTTPS for all web traffic'
            },
            53: {
                'category': 'infrastructure',
                'security_note': 'DNS service - required for domain name resolution',
                'recommendation': 'Ensure DNS configuration follows security best practices'
            }
        }
        
        # Ports that should trigger security review
        self.review_required_ports = {
            22: {'risk': 'medium', 'reason': 'SSH access - ensure strong authentication and access controls'},
            25: {'risk': 'medium', 'reason': 'SMTP service - verify it\'s not an open relay'},
            110: {'risk': 'medium', 'reason': 'POP3 transmits passwords in cleartext - use POP3S instead'},
            143: {'risk': 'medium', 'reason': 'IMAP transmits passwords in cleartext - use IMAPS instead'},
            8080: {'risk': 'medium', 'reason': 'Alternative HTTP port - review what service is running'},
            8443: {'risk': 'medium', 'reason': 'Alternative HTTPS port - review what service is running'}
        }
        
        # High-risk ports that should generally not be exposed
        self.high_risk_ports = {
            21: {'risk': 'high', 'reason': 'FTP often transmits credentials in cleartext'},
            23: {'risk': 'critical', 'reason': 'Telnet transmits all data including passwords in cleartext'},
            135: {'risk': 'high', 'reason': 'MSRPC has many known vulnerabilities and is often targeted'},
            139: {'risk': 'high', 'reason': 'NetBIOS is frequently exploited in Windows environments'},
            445: {'risk': 'high', 'reason': 'SMB has been the target of many critical exploits (EternalBlue, etc.)'},
            1433: {'risk': 'critical', 'reason': 'MS SQL Server should not be exposed to the internet'},
            1521: {'risk': 'critical', 'reason': 'Oracle database should not be exposed to the internet'},
            3306: {'risk': 'high', 'reason': 'MySQL database should generally not be exposed to the internet'},
            3389: {'risk': 'critical', 'reason': 'RDP is frequently targeted by brute force attacks'},
            5432: {'risk': 'high', 'reason': 'PostgreSQL database should generally not be exposed to the internet'},
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
            
            # Categorize the open ports
            standard_ports = []
            review_ports = []
            high_risk_ports = []
            unknown_ports = []
            
            for port_info in open_ports:
                port_num = port_info['port']
                
                if port_num in self.standard_web_ports:
                    standard_ports.append(port_info)
                elif port_num in self.review_required_ports:
                    review_ports.append(port_info)
                elif port_num in self.high_risk_ports:
                    high_risk_ports.append(port_info)
                else:
                    unknown_ports.append(port_info)
            
            # Report standard web services (informational only)
            if standard_ports:
                self._add_standard_ports_finding(findings, standard_ports)
            
            # Report ports that need review
            if review_ports:
                self._add_review_ports_finding(findings, review_ports)
            
            # Report high-risk ports
            if high_risk_ports:
                self._add_high_risk_ports_finding(findings, high_risk_ports)
            
            # Report unknown/uncommon ports
            if unknown_ports:
                self._add_unknown_ports_finding(findings, unknown_ports)
            
            # Add overall summary if multiple categories exist
            if len([x for x in [standard_ports, review_ports, high_risk_ports, unknown_ports] if x]) > 1:
                self._add_port_summary_finding(findings, open_ports)
                
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
    
    def _add_standard_ports_finding(self, findings, standard_ports):
        """Add finding for standard web ports (informational)"""
        port_details = []
        for port_info in standard_ports:
            port_num = port_info['port']
            standard_info = self.standard_web_ports[port_num]
            port_details.append({
                'port': port_num,
                'service': port_info['service'],
                'category': standard_info['category'],
                'security_note': standard_info['security_note'],
                'recommendation': standard_info['recommendation']
            })
        
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in standard_ports])
        
        findings.append({
            'name': 'Standard Web Services Detected',
            'description': f'Found standard web services on {self.hostname}: {port_list}. These are normal and expected for web servers.',
            'severity': 'info',
            'details': {
                'hostname': self.hostname,
                'standard_ports': port_details,
                'page_url': self.url,
                'impact': 'These are standard, expected services for web servers.',
                'recommendation': 'No action required - these are normal web services.'
            }
        })
    
    def _add_review_ports_finding(self, findings, review_ports):
        """Add finding for ports that require security review"""
        port_details = []
        for port_info in review_ports:
            port_num = port_info['port']
            review_info = self.review_required_ports[port_num]
            port_details.append({
                'port': port_num,
                'service': port_info['service'],
                'risk_level': review_info['risk'],
                'reason': review_info['reason']
            })
        
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in review_ports])
        
        findings.append({
            'name': 'Services Requiring Security Review',
            'description': f'Found {len(review_ports)} services that should be reviewed for security: {port_list}',
            'severity': 'medium',
            'details': {
                'hostname': self.hostname,
                'review_ports': port_details,
                'page_url': self.url,
                'impact': 'These services may need security configuration review.',
                'recommendation': 'Review security configuration and access controls for these services.'
            }
        })
    
    def _add_high_risk_ports_finding(self, findings, high_risk_ports):
        """Add finding for high-risk ports"""
        port_details = []
        highest_risk = 'medium'
        
        for port_info in high_risk_ports:
            port_num = port_info['port']
            risk_info = self.high_risk_ports[port_num]
            port_details.append({
                'port': port_num,
                'service': port_info['service'],
                'risk_level': risk_info['risk'],
                'reason': risk_info['reason']
            })
            
            # Track highest risk level
            if risk_info['risk'] == 'critical':
                highest_risk = 'high'  # Map to our severity levels
            elif risk_info['risk'] == 'high' and highest_risk != 'high':
                highest_risk = 'high'
        
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in high_risk_ports])
        
        findings.append({
            'name': 'High-Risk Services Exposed',
            'description': f'Found {len(high_risk_ports)} high-risk services exposed to the internet: {port_list}',
            'severity': highest_risk,
            'details': {
                'hostname': self.hostname,
                'high_risk_ports': port_details,
                'page_url': self.url,
                'impact': 'These services pose significant security risks when exposed to the internet.',
                'recommendation': 'Consider closing these ports or restricting access with firewall rules.'
            }
        })
        
        # Add individual findings for critical ports
        for port_info in high_risk_ports:
            port_num = port_info['port']
            risk_info = self.high_risk_ports[port_num]
            if risk_info['risk'] == 'critical':
                findings.append({
                    'name': f'Critical: {port_info["service"]} Service Exposed (Port {port_num})',
                    'description': f'Port {port_num} ({port_info["service"]}) is exposed: {risk_info["reason"]}',
                    'severity': 'high',
                    'details': {
                        'hostname': self.hostname,
                        'port': port_num,
                        'service': port_info['service'],
                        'page_url': self.url,
                        'impact': risk_info['reason'],
                        'recommendation': f'Immediately close port {port_num} or restrict access with firewall rules.'
                    }
                })
    
    def _add_unknown_ports_finding(self, findings, unknown_ports):
        """Add finding for unknown/uncommon ports"""
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in unknown_ports])
        
        findings.append({
            'name': 'Uncommon Services Detected',
            'description': f'Found {len(unknown_ports)} uncommon or unknown services: {port_list}',
            'severity': 'low',
            'details': {
                'hostname': self.hostname,
                'unknown_ports': unknown_ports,
                'page_url': self.url,
                'impact': 'Uncommon services may indicate custom applications or potential security risks.',
                'recommendation': 'Review each service to ensure it is necessary and properly secured.'
            }
        })
    
    def _add_port_summary_finding(self, findings, all_open_ports):
        """Add overall summary of all open ports"""
        port_list = ", ".join([f"{p['port']}/{p['service']}" for p in all_open_ports])
        
        findings.append({
            'name': 'Open Ports Summary',
            'description': f'Total of {len(all_open_ports)} open ports detected on {self.hostname}: {port_list}',
            'severity': 'info',
            'details': {
                'hostname': self.hostname,
                'total_ports': len(all_open_ports),
                'open_ports': all_open_ports,
                'page_url': self.url,
                'ports_list': port_list,
                'impact': 'Multiple open ports increase the potential attack surface.',
                'recommendation': 'Review all services and close any that are not required.'
            }
        })
    
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