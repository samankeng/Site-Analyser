# backend/scanner/services/active_scanner.py - FIXED VERSION

import logging
from django.utils import timezone
from scanner.models import ScanResult
from .active_vulnerability_scanner import ActiveVulnerabilityScanner

logger = logging.getLogger(__name__)

class ActiveScanService:
    """Service for running active security scans"""
    
    def __init__(self, scan, user=None, compliance_mode='strict', auto_complete=True, skip_rate_limiting=False):
        self.scan = scan
        self.user = user or scan.user
        self.compliance_mode = compliance_mode or getattr(scan, 'compliance_mode', 'strict')
        self.auto_complete = auto_complete
        self.skip_rate_limiting = skip_rate_limiting
        
        logger.info(f"ActiveScanService initialized for {scan.target_url} (auto_complete={auto_complete}, skip_rate_limiting={skip_rate_limiting})")
    
    def run(self):
        """Run the active scan"""
        try:
            # Update scan status to in_progress if auto_completing
            if self.auto_complete:
                self.scan.status = 'in_progress'
                self.scan.started_at = timezone.now()
                self.scan.save()
                logger.info(f"Active scan started for {self.scan.target_url}")
            
            # Run active vulnerability scanning
            findings = self._run_active_vulnerability_scan()
            
            # Process and save findings
            self._save_findings(findings)
            
            # Complete the scan if auto_complete is enabled
            if self.auto_complete:
                from celery_app.tasks import complete_scan_with_ai_analysis
                complete_scan_with_ai_analysis(self.scan)
                logger.info(f"Active scan completed for {self.scan.target_url}")
            else:
                logger.info(f"Active scan phase completed for {self.scan.target_url} (auto_complete=False)")
            
        except Exception as e:
            logger.exception(f"Error in active scan for {self.scan.target_url}: {str(e)}")
            
            # Update scan status to failed if auto_completing
            if self.auto_complete:
                self.scan.status = 'failed'
                self.scan.error_message = str(e)
                self.scan.completed_at = timezone.now()
                self.scan.save()
            
            raise
    
    def _run_active_vulnerability_scan(self):
        """Run active vulnerability scanning with proper error handling"""
        try:
            scanner = ActiveVulnerabilityScanner(
                url=self.scan.target_url,
                user=self.user,
                compliance_mode=self.compliance_mode,
                skip_rate_limiting=self.skip_rate_limiting
            )
            
            findings = scanner.scan()
            
            # CRITICAL FIX: Ensure findings is always a list
            if findings is None:
                logger.warning("Active vulnerability scanner returned None, using empty list")
                findings = []
            elif not isinstance(findings, list):
                logger.warning(f"Active vulnerability scanner returned {type(findings)}, converting to list")
                findings = list(findings) if findings else []
            
            logger.info(f"Active vulnerability scan completed with {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.exception(f"Error in active vulnerability scanning: {str(e)}")
            # Return a finding about the scan error instead of failing completely
            return [{
                'name': 'Active Scan Error',
                'description': f'Error during active vulnerability scanning: {str(e)}',
                'severity': 'info',
                'details': {
                    'error': str(e),
                    'scan_type': 'active',
                    'scan_id': str(self.scan.id),
                    'target_url': self.scan.target_url
                }
            }]
    
    def _save_findings(self, findings):
        """Save scan findings to database with proper error handling"""
        if not findings:
            logger.info("No active scan findings to save")
            return
        
        saved_count = 0
        error_count = 0
        
        # CRITICAL FIX: Ensure findings is iterable
        if not isinstance(findings, (list, tuple)):
            logger.error(f"Findings is not iterable: {type(findings)}")
            findings = []
        
        for finding in findings:
            try:
                # CRITICAL FIX: Ensure finding is a dictionary
                if not isinstance(finding, dict):
                    logger.warning(f"Skipping non-dict finding: {type(finding)}")
                    error_count += 1
                    continue
                
                # Extract finding data with defaults
                name = finding.get('name', 'Unknown Active Finding')
                description = finding.get('description', 'No description available')
                severity = finding.get('severity', 'info')
                details = finding.get('details', {})
                
                # Ensure details is a dictionary
                if not isinstance(details, dict):
                    details = {'original_details': str(details)}
                
                # Add scan metadata
                details.update({
                    'scan_type': 'active',
                    'scan_id': str(self.scan.id),
                    'compliance_mode': self.compliance_mode,
                    'found_at': timezone.now().isoformat(),
                    'skip_rate_limiting': self.skip_rate_limiting
                })
                
                # Create ScanResult
                scan_result = ScanResult.objects.create(
                    scan=self.scan,
                    category='active_vulnerabilities',  # Prefix with 'active_' to avoid conflicts
                    name=name,
                    description=description,
                    severity=severity,
                    details=details
                )
                
                saved_count += 1
                logger.debug(f"Saved active finding: {name}")
                
            except Exception as e:
                error_count += 1
                logger.error(f"Error saving active finding: {str(e)}")
                logger.debug(f"Problem finding data: {finding}")
        
        logger.info(f"Active scan findings saved: {saved_count} successful, {error_count} errors")
        
        # If we had errors, create a summary finding
        if error_count > 0:
            ScanResult.objects.create(
                scan=self.scan,
                category='active_scan_issues',
                name='Active Scan Processing Errors',
                description=f'Encountered {error_count} errors while processing active scan findings',
                severity='info',
                details={
                    'error_count': error_count,
                    'saved_count': saved_count,
                    'scan_type': 'active',
                    'scan_id': str(self.scan.id),
                    'recommendation': 'Review scan logs for details about processing errors'
                }
            )