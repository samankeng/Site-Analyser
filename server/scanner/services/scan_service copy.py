# backend/scanner/services/scan_service.py

import logging
from django.utils import timezone
from ..models import ScanResult, Scan
from .header_scanner import HeaderScanner
from .ssl_scanner import SslScanner
# from .vulnerability_scanner import VulnerabilityScanner
from .content_scanner import ContentScanner
from .port_scanner import PortScanner
from .csp_scanner import CspScanner
from .cookie_scanner import CookieScanner
from .cors_scanner import CorsScanner
from .server_analyzer import ServerAnalyzer
from ai_analyzer.ml.anomaly_detection.model import AnomalyDetectionModel

logger = logging.getLogger(__name__)

class ScanService:
    """Main service for orchestrating security scans with enhanced details"""
    
    def __init__(self, scan):
        self.scan = scan
        self.target_url = scan.target_url
        self.scan_types = scan.scan_types
        self.anomaly_detector = AnomalyDetectionModel()
        
        # Initialize scanners
        self.scanners = {
            'headers': HeaderScanner(self.target_url),
            'ssl': SslScanner(self.target_url),
            # 'vulnerabilities': VulnerabilityScanner(self.target_url),
            'content': ContentScanner(self.target_url),
            'ports': PortScanner(self.target_url),
            'csp': CspScanner(self.target_url),
            'cookies': CookieScanner(self.target_url),
            'cors': CorsScanner(self.target_url),
            'server': ServerAnalyzer(self.target_url),
        }
    
    def run(self):
        """Run all requested scan types with enhanced detail tracking"""
        logger.info(f"Starting scan for {self.target_url} with types: {self.scan_types}")
        
        try:
            # Update scan status to in_progress and set started timestamp
            self.scan.status = 'in_progress'
            self.scan.started_at = timezone.now()
            self.scan.save()
            
            # Run each requested scanner
            for scan_type in self.scan_types:
                if scan_type in self.scanners:
                    self._run_scanner(scan_type)
                    # Run anomaly detection on results
                    self._run_anomaly_detection_on_results(scan_type)
                else:
                    logger.warning(f"Unknown scan type: {scan_type}")
            
            # Check if the scan was cancelled
            scan = Scan.objects.get(id=self.scan.id)  # Refresh from DB
            if scan.status == 'failed' and 'cancelled by user' in scan.error_message:
                logger.info(f"Scan was cancelled by user: {self.target_url}")
                return
            
            # Mark scan as completed
            self.scan.status = 'completed'
            self.scan.completed_at = timezone.now()
            self.scan.save()
            
            logger.info(f"Scan completed for {self.target_url}")
            
        except Exception as e:
            # Mark scan as failed if there's an exception
            logger.exception(f"Scan failed for {self.target_url}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()
            
    def _run_anomaly_detection_on_results(self, scan_type):
        """Run anomaly detection on scan results in real-time"""
        recent_results = ScanResult.objects.filter(
            scan=self.scan,
            category=scan_type
        ).order_by('-created_at')[:10]  # Get latest results
        
        scan_data = self._prepare_scan_data_for_anomaly_detection(recent_results)
        anomalies = self.anomaly_detector.detect_anomalies(scan_data)
        
        if anomalies.get('is_anomaly'):
            self._log_anomaly_findings(anomalies, scan_type)
    
    def _prepare_scan_data_for_anomaly_detection(self, scan_results):
        """Prepare scan results for anomaly detection"""
        scan_data = {
            'response_time': 0,
            'header_count': 0,
            'ssl': {},
            'content': {},
            'headers': {},
            'performance': {}
        }
        
        for result in scan_results:
            if result.category == 'headers':
                scan_data['headers'].update(result.details)
                scan_data['header_count'] = len(result.details)
            elif result.category == 'ssl':
                scan_data['ssl'].update(result.details)
            elif result.category == 'content':
                scan_data['content'].update(result.details)
            elif result.category == 'performance':
                scan_data['performance'].update(result.details)
                scan_data['response_time'] = result.details.get('response_time', 0)
        
        return scan_data
    
    def _log_anomaly_findings(self, anomalies, scan_type):
        """Log anomaly findings as scan results"""
        for anomaly in anomalies.get('anomalies', []):
            ScanResult.objects.create(
                scan=self.scan,
                category='anomaly',
                name=f"Anomaly Detected: {anomaly['component']}",
                description=anomaly['description'],
                severity=anomaly['severity'],
                details={
                    'anomaly_score': anomaly['score'],
                    'scan_type': scan_type,
                    'recommendation': anomaly.get('recommendation', ''),
                    'timestamp': timezone.now().isoformat()
                }
            )

    def _run_scanner(self, scan_type):
        """Run a specific scanner and save results with enhanced details"""
        try:
            logger.info(f"Running {scan_type} scan for {self.target_url}")
            scanner = self.scanners[scan_type]
            findings = scanner.scan()
            
            # Save findings to database
            for finding in findings:
                # Add timestamp for when issue was found
                finding_details = finding.get('details', {})
                finding_details['found_at'] = timezone.now().isoformat()
                
                # Add scan metadata
                finding_details['scan_id'] = str(self.scan.id)
                finding_details['target_url'] = self.target_url
                
                # Create scan result with enhanced details
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
                    'scan_type': scan_type,
                    'target_url': self.target_url,
                    'timestamp': timezone.now().isoformat()
                }
            )