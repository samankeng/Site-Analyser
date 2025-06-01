# backend/scanner/services/passive_scanner.py

import logging
from django.utils import timezone
from ..models import ScanResult, Scan
from .header_scanner import HeaderScanner
from .ssl_scanner import SslScanner
from .content_scanner import ContentScanner
from .port_scanner import PortScanner
from .csp_scanner import CspScanner
from .cookie_scanner import CookieScanner
from .cors_scanner import CorsScanner
from .server_analyzer import ServerAnalyzer
from .passive_vulnerability_scanner import PassiveVulnerabilityScanner

logger = logging.getLogger(__name__)

class PassiveScanService:
    """
    Passive security scanner that performs only non-intrusive scanning.
    Safe to run on any website without authorization concerns.
    """
    
    def __init__(self, scan):
        self.scan = scan
        self.target_url = scan.target_url
        self.scan_types = scan.scan_types
        
        # Initialize passive scanners only
        self.passive_scanners = {
            'headers': HeaderScanner(self.target_url),
            'ssl': SslScanner(self.target_url),
            'content': ContentScanner(self.target_url),
            'ports': PortScanner(self.target_url),
            'csp': CspScanner(self.target_url),
            'cookies': CookieScanner(self.target_url),
            'cors': CorsScanner(self.target_url),
            'server': ServerAnalyzer(self.target_url),
            'vulnerabilities': PassiveVulnerabilityScanner(self.target_url),
        }
    
    def run(self):
        """Run passive security scanning only"""
        logger.info(f"Starting passive scan for {self.target_url} with types: {self.scan_types}")
        
        try:
            # Update scan status to in_progress and set started timestamp
            self.scan.status = 'in_progress'
            self.scan.started_at = timezone.now()
            self.scan.save()
            
            # Run each requested passive scanner
            for scan_type in self.scan_types:
                if scan_type in self.passive_scanners:
                    self._run_passive_scanner(scan_type)
                else:
                    logger.warning(f"Unknown passive scan type: {scan_type}")
            
            # Check if the scan was cancelled
            scan = Scan.objects.get(id=self.scan.id)  # Refresh from DB
            if scan.status == 'failed' and 'cancelled by user' in scan.error_message:
                logger.info(f"Passive scan was cancelled by user: {self.target_url}")
                return
            
            # Mark scan as completed
            self.scan.status = 'completed'
            self.scan.completed_at = timezone.now()
            self.scan.save()
            
            logger.info(f"Passive scan completed for {self.target_url}")
            
        except Exception as e:
            # Mark scan as failed if there's an exception
            logger.exception(f"Passive scan failed for {self.target_url}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()
    
    def _run_passive_scanner(self, scan_type):
        """Run a specific passive scanner and save results"""
        try:
            logger.info(f"Running passive {scan_type} scan for {self.target_url}")
            scanner = self.passive_scanners[scan_type]
            findings = scanner.scan()
            
            # Save findings to database
            for finding in findings:
                # Add timestamp for when issue was found
                finding_details = finding.get('details', {})
                finding_details['found_at'] = timezone.now().isoformat()
                finding_details['scan_type'] = 'passive'
                
                # Add scan metadata
                finding_details['scan_id'] = str(self.scan.id)
                finding_details['target_url'] = self.target_url
                
                # Create scan result
                ScanResult.objects.create(
                    scan=self.scan,
                    category=scan_type,
                    name=finding['name'],
                    description=finding['description'],
                    severity=finding['severity'],
                    details=finding_details
                )
                
            logger.info(f"Completed passive {scan_type} scan for {self.target_url} - Found {len(findings)} issues")
            
        except Exception as e:
            logger.exception(f"Error in passive {scan_type} scan for {self.target_url}: {str(e)}")
            # Create an error result
            ScanResult.objects.create(
                scan=self.scan,
                category=scan_type,
                name=f"Error in passive {scan_type} scan",
                description=str(e),
                severity='info',
                details={
                    'error': str(e),
                    'scan_type': 'passive',
                    'target_url': self.target_url,
                    'timestamp': timezone.now().isoformat()
                }
            )