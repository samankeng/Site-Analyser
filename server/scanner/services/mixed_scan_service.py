# backend/scanner/services/mixed_scan_service.py - NEW FILE

import logging
from django.utils import timezone
from ..models import ScanResult, Scan
from .active_scanner import ActiveScanService
from .passive_scanner import PassiveScanService

logger = logging.getLogger(__name__)

class MixedScanService:
    """
    Orchestrates both active and passive scans to avoid duplicates.
    Ensures each scan type runs only once.
    """
    
    def __init__(self, scan, user=None, compliance_mode='strict'):
        self.scan = scan
        self.target_url = scan.target_url
        self.scan_types = scan.scan_types
        self.user = user
        self.compliance_mode = compliance_mode
        
        # Define which scan types are active vs passive
        self.active_scan_types = {'vulnerabilities'}  # Only true active scans
        self.passive_scan_types = {
            'headers', 'ssl', 'content', 'csp', 'cookies', 
            'cors', 'server', 'ports'  # ports can be passive too
        }
    
    def run(self):
        """Run both active and passive scans without duplicates"""
        logger.info(f"Starting mixed scan for {self.target_url} with types: {self.scan_types}")
        
        try:
            # Update scan status
            self.scan.status = 'in_progress'
            self.scan.started_at = timezone.now()
            self.scan.save()
            
            # Separate scan types
            active_types = [st for st in self.scan_types if st in self.active_scan_types]
            passive_types = [st for st in self.scan_types if st in self.passive_scan_types]
            
            # Run passive scans first (safer)
            if passive_types:
                logger.info(f"Running passive scans: {passive_types}")
                passive_service = PassiveScanService(self._create_sub_scan(passive_types))
                passive_service.run()
            
            # Run active scans if authorized
            if active_types:
                logger.info(f"Running active scans: {active_types}")
                active_service = ActiveScanService(
                    self._create_sub_scan(active_types), 
                    user=self.user, 
                    compliance_mode=self.compliance_mode
                )
                active_service.run()
            
            # Check if cancelled
            scan = Scan.objects.get(id=self.scan.id)
            if scan.status == 'failed' and 'cancelled by user' in scan.error_message:
                logger.info(f"Mixed scan was cancelled by user: {self.target_url}")
                return
            
            # Complete the scan
            self.scan.status = 'completed'
            self.scan.completed_at = timezone.now()
            self.scan.save()
            
            logger.info(f"Mixed scan completed for {self.target_url}")
            
        except Exception as e:
            logger.exception(f"Mixed scan failed for {self.target_url}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()
    
    def _create_sub_scan(self, scan_types):
        """Create a temporary scan object for sub-services"""
        # Create a copy of the scan with specific types
        class SubScan:
            def __init__(self, original_scan, scan_types):
                self.id = original_scan.id
                self.target_url = original_scan.target_url
                self.scan_types = scan_types
                self.status = original_scan.status
                self.started_at = original_scan.started_at
                self.completed_at = original_scan.completed_at
                self.error_message = original_scan.error_message
                
            def save(self):
                # Don't save sub-scans, let the main scan handle status
                pass
        
        return SubScan(self.scan, scan_types)