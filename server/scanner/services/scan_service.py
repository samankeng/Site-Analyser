# backend/scanner/services/scan_service.py

import logging
from django.utils import timezone
from django.conf import settings
from ..models import ScanResult, Scan
from .header_scanner import HeaderScanner
from .ssl_scanner import SslScanner
from .content_scanner import ContentScanner
from .port_scanner import PortScanner
from .csp_scanner import CspScanner
from .cookie_scanner import CookieScanner
from .cors_scanner import CorsScanner
from .server_analyzer import ServerAnalyzer
from ai_analyzer.ml.anomaly_detection.model import AnomalyDetectionModel

logger = logging.getLogger(__name__)

class ScanCompletionMixin:
    """Mixin to handle scan completion and trigger AI analysis"""
    
    def complete_scan(self, scan):
        """Complete the scan and trigger AI analysis if enabled"""
        try:
            # Import and use the centralized completion logic from tasks
            from celery_app.tasks import complete_scan_with_ai_analysis
            
            # This handles status update and AI analysis (no report creation)
            complete_scan_with_ai_analysis(scan)
            
        except ImportError:
            # Fallback to local implementation if tasks not available
            logger.warning("Could not import tasks module, using local completion logic")
            
            # Update scan status
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
            
            # Trigger AI analysis if enabled
            if getattr(settings, 'AI_ANALYZER_ENABLED', True):
                self.trigger_ai_analysis(scan)
                
            logger.info(f"Scan {scan.id} completed successfully")
            
        except Exception as e:
            logger.exception(f"Error completing scan {scan.id}: {str(e)}")
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
    
    def trigger_ai_analysis(self, scan):
        """Trigger AI analysis for completed scan"""
        try:
            # Import here to avoid circular imports
            from celery_app.tasks import run_ai_analysis_task
            
            # Queue the AI analysis task
            run_ai_analysis_task.delay(str(scan.id))
            logger.info(f"AI analysis task queued for scan {scan.id}")
            
        except Exception as e:
            logger.warning(f"Failed to trigger AI analysis for scan {scan.id}: {str(e)}")

class ScanService(ScanCompletionMixin):
    """Main service for orchestrating security scans with enhanced details"""
    
    def __init__(self, scan):
        self.scan = scan
        self.target_url = scan.target_url
        self.scan_types = scan.scan_types
        
        # Initialize anomaly detector only if needed
        try:
            self.anomaly_detector = AnomalyDetectionModel()
        except Exception as e:
            logger.warning(f"Could not initialize anomaly detector: {str(e)}")
            self.anomaly_detector = None
        
        # Initialize scanners - only passive scanners here
        # Active vulnerability scanning is handled separately
        self.scanners = {
            'headers': HeaderScanner(self.target_url),
            'ssl': SslScanner(self.target_url),
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
                    
                    # Run anomaly detection on results if available
                    if self.anomaly_detector:
                        try:
                            self._run_anomaly_detection_on_results(scan_type)
                        except Exception as e:
                            logger.warning(f"Anomaly detection failed for {scan_type}: {str(e)}")
                else:
                    logger.warning(f"Unknown scan type: {scan_type}")
            
            # Check if the scan was cancelled
            scan = Scan.objects.get(id=self.scan.id)  # Refresh from DB
            if scan.status == 'failed' and scan.error_message and 'cancelled by user' in scan.error_message:
                logger.info(f"Scan was cancelled by user: {self.target_url}")
                return
            
            # Complete scan and trigger AI analysis (no automatic report creation)
            self.complete_scan(self.scan)
            logger.info(f"Scan completed for {self.target_url}")
            
        except Exception as e:
            # Mark scan as failed if there's an exception
            logger.exception(f"Scan failed for {self.target_url}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()
            raise
            
    def _run_anomaly_detection_on_results(self, scan_type):
        """Run anomaly detection on scan results in real-time"""
        if not self.anomaly_detector:
            return
            
        recent_results = ScanResult.objects.filter(
            scan=self.scan,
            category=scan_type
        ).order_by('-created_at')[:10]  # Get latest results
        
        if not recent_results:
            return
        
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
            try:
                if result.category == 'headers':
                    if isinstance(result.details, dict):
                        scan_data['headers'].update(result.details)
                        scan_data['header_count'] = len(result.details)
                elif result.category == 'ssl':
                    if isinstance(result.details, dict):
                        scan_data['ssl'].update(result.details)
                elif result.category == 'content':
                    if isinstance(result.details, dict):
                        scan_data['content'].update(result.details)
                elif result.category == 'performance':
                    if isinstance(result.details, dict):
                        scan_data['performance'].update(result.details)
                        scan_data['response_time'] = result.details.get('response_time', 0)
            except Exception as e:
                logger.warning(f"Error preparing anomaly detection data for result {result.id}: {str(e)}")
        
        return scan_data
    
    def _log_anomaly_findings(self, anomalies, scan_type):
        """Log anomaly findings as scan results"""
        for anomaly in anomalies.get('anomalies', []):
            try:
                ScanResult.objects.create(
                    scan=self.scan,
                    category='anomaly',
                    name=f"Anomaly Detected: {anomaly.get('component', 'Unknown')}",
                    description=anomaly.get('description', 'Anomaly detected without description'),
                    severity=anomaly.get('severity', 'low'),
                    details={
                        'anomaly_score': anomaly.get('score', 0),
                        'scan_type': scan_type,
                        'recommendation': anomaly.get('recommendation', ''),
                        'timestamp': timezone.now().isoformat(),
                        'anomaly_data': anomaly
                    }
                )
            except Exception as e:
                logger.error(f"Error creating anomaly scan result: {str(e)}")

    def _run_scanner(self, scan_type):
        """Run a specific scanner and save results with enhanced details"""
        try:
            logger.info(f"Running {scan_type} scan for {self.target_url}")
            scanner = self.scanners[scan_type]
            findings = scanner.scan()
            
            # Save findings to database
            for finding in findings:
                try:
                    # Validate finding structure
                    if not isinstance(finding, dict):
                        logger.error(f"Invalid finding format from {scan_type} scanner: {finding}")
                        continue
                    
                    if not all(key in finding for key in ['name', 'description', 'severity']):
                        logger.error(f"Missing required fields in finding from {scan_type}: {finding}")
                        continue
                    
                    # Add timestamp for when issue was found
                    finding_details = finding.get('details', {})
                    if not isinstance(finding_details, dict):
                        finding_details = {}
                    
                    finding_details['found_at'] = timezone.now().isoformat()
                    finding_details['scan_type'] = 'passive'  # ScanService only handles passive scans
                    
                    # Add scan metadata
                    finding_details['scan_id'] = str(self.scan.id)
                    finding_details['target_url'] = self.target_url
                    
                    # Validate severity
                    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
                    severity = finding.get('severity', 'info').lower()
                    if severity not in valid_severities:
                        logger.warning(f"Invalid severity '{severity}' from {scan_type}, defaulting to 'info'")
                        severity = 'info'
                    
                    # Create scan result with enhanced details
                    ScanResult.objects.create(
                        scan=self.scan,
                        category=scan_type,
                        name=finding['name'][:100],  # Ensure it fits the field
                        description=finding['description'],
                        severity=severity,
                        details=finding_details
                    )
                    
                except Exception as e:
                    logger.error(f"Error saving finding from {scan_type}: {str(e)}, finding: {finding}")
                    continue
                
            logger.info(f"Completed {scan_type} scan for {self.target_url} - Found {len(findings)} issues")
            
        except Exception as e:
            logger.exception(f"Error in {scan_type} scan for {self.target_url}: {str(e)}")
            # Create an error result
            try:
                ScanResult.objects.create(
                    scan=self.scan,
                    category=scan_type,
                    name=f"Error in {scan_type} scan",
                    description=str(e),
                    severity='info',
                    details={
                        'error': str(e),
                        'scan_type': 'passive',
                        'target_url': self.target_url,
                        'timestamp': timezone.now().isoformat()
                    }
                )
            except Exception as inner_e:
                logger.error(f"Failed to create error scan result: {str(inner_e)}")