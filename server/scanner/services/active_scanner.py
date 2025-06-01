# backend/scanner/services/active_scanner.py - ENHANCED VERSION

import logging
from django.utils import timezone
from ..models import ScanResult, Scan
from .active_vulnerability_scanner import ActiveVulnerabilityScanner

# Import passive scanners for non-intrusive tests
from .header_scanner import HeaderScanner
from .ssl_scanner import SslScanner
from .content_scanner import ContentScanner
from .port_scanner import PortScanner
from .csp_scanner import CspScanner
from .cookie_scanner import CookieScanner
from .cors_scanner import CorsScanner
from .server_analyzer import ServerAnalyzer

logger = logging.getLogger(__name__)

class ActiveScanService:
    """
    Enhanced active security scanner that performs both active and passive testing.
    REQUIRES EXPLICIT AUTHORIZATION - Only use on systems you own or have permission to test.
    """
    
    def __init__(self, scan, user=None, compliance_mode='strict'):
        self.scan = scan
        self.target_url = scan.target_url
        self.scan_types = scan.scan_types
        self.user = user
        self.compliance_mode = compliance_mode
        
        # Initialize ALL scanners with compliance mode
        self.scanners = {
            # ACTIVE-ONLY SCANNERS (require authorization)
            'vulnerabilities': ActiveVulnerabilityScanner(
                self.target_url, 
                user=user, 
                compliance_mode=compliance_mode
            ),
            
            # PASSIVE SCANNERS (safe to run during active scan)
            'headers': HeaderScanner(self.target_url),
            'ssl': SslScanner(self.target_url),
            'content': ContentScanner(self.target_url),
            'csp': CspScanner(self.target_url),
            'cookies': CookieScanner(self.target_url),
            'cors': CorsScanner(self.target_url),
            'server': ServerAnalyzer(self.target_url),
            
            # PORT SCANNING (requires authorization)
            'ports': PortScanner(self.target_url),
        }
    
    def run(self):
        """Run comprehensive active security scanning with compliance checks"""
        logger.info(f"Starting active scan for {self.target_url} with types: {self.scan_types} (mode: {self.compliance_mode})")
        
        try:
            # Pre-scan authorization check
            if not self._check_authorization():
                raise Exception("Active scanning requires explicit authorization")
            
            # Update scan status to in_progress and set started timestamp
            self.scan.status = 'in_progress'
            self.scan.started_at = timezone.now()
            self.scan.save()
            
            # Run each requested scanner
            for scan_type in self.scan_types:
                if scan_type in self.scanners:
                    self._run_scanner(scan_type)
                else:
                    logger.warning(f"Unknown scan type: {scan_type}")
            
            # Check if the scan was cancelled
            scan = Scan.objects.get(id=self.scan.id)  # Refresh from DB
            if scan.status == 'failed' and 'cancelled by user' in scan.error_message:
                logger.info(f"Active scan was cancelled by user: {self.target_url}")
                return
            
            # Mark scan as completed
            self.scan.status = 'completed'
            self.scan.completed_at = timezone.now()
            self.scan.save()
            
            logger.info(f"Active scan completed for {self.target_url}")
            
        except Exception as e:
            # Mark scan as failed if there's an exception
            logger.exception(f"Active scan failed for {self.target_url}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()
    
    def _check_authorization(self):
        """Check if user has authorization for active scanning"""
        from urllib.parse import urlparse
        
        domain = urlparse(self.target_url).netloc
        
        # Check for development domains that don't require authorization
        development_domains = [
            'badssl.com', 'testphp.vulnweb.com', 'demo.testfire.net',
            'httpbin.org', 'localhost', '127.0.0.1', 'reqbin.com'
        ]
        
        is_dev_domain = any(dev_domain in domain for dev_domain in development_domains)
        
        if is_dev_domain:
            return True
        
        # For production domains, check authorization
        if hasattr(self.scan, 'authorization') and self.scan.authorization:
            return self.scan.authorization.is_valid()
        
        return False
    
    def _run_scanner(self, scan_type):
        """Run a specific scanner and save results"""
        try:
            logger.info(f"Running {scan_type} scan for {self.target_url}")
            scanner = self.scanners[scan_type]
            findings = scanner.scan()
            
            # Determine scan method based on scanner type
            scan_method = 'active' if scan_type in ['vulnerabilities', 'ports'] else 'passive'
            
            # Save findings to database
            for finding in findings:
                # Add timestamp for when issue was found
                finding_details = finding.get('details', {})
                finding_details['found_at'] = timezone.now().isoformat()
                finding_details['scan_type'] = scan_method
                finding_details['compliance_mode'] = self.compliance_mode
                
                # Add scan metadata
                finding_details['scan_id'] = str(self.scan.id)
                finding_details['target_url'] = self.target_url
                
                # Add authorization info for active tests
                if scan_method == 'active':
                    finding_details['authorized'] = True
                    finding_details['authorization_method'] = 'pre-authorized-domain'
                
                # Create scan result
                ScanResult.objects.create(
                    scan=self.scan,
                    category=scan_type,
                    name=finding['name'],
                    description=finding['description'],
                    severity=finding['severity'],
                    details=finding_details
                )
                
            logger.info(f"Completed {scan_type} scan for {self.target_url} - Found {len(findings)} issues")
            
        except Exception as e:
            logger.exception(f"Error in {scan_type} scan for {self.target_url}: {str(e)}")
            # Create an error result
            ScanResult.objects.create(
                scan=self.scan,
                category=scan_type,
                name=f"Error in {scan_type} scan",
                description=str(e),
                severity='info',
                details={
                    'error': str(e),
                    'scan_type': 'active',
                    'compliance_mode': self.compliance_mode,
                    'target_url': self.target_url,
                    'timestamp': timezone.now().isoformat()
                }
            )