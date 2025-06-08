# backend/celery_app/tasks.py - COMPLETE FINAL VERSION

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import uuid

logger = logging.getLogger(__name__)

def complete_scan_with_ai_analysis(scan):
    """Helper function to complete scan and trigger AI analysis (no report creation)"""
    try:
        # Update scan status
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()
        
        # Trigger AI analysis if enabled
        if getattr(settings, 'AI_ANALYZER_ENABLED', True):
            logger.info(f"Triggering AI analysis for completed scan {scan.id}")
            run_ai_analysis_task.delay(str(scan.id))
        
        logger.info(f"Scan {scan.id} completed successfully")
        
    except Exception as e:
        logger.exception(f"Error completing scan {scan.id}: {str(e)}")
        scan.status = 'failed'
        scan.error_message = str(e)
        scan.completed_at = timezone.now()
        scan.save()

# Keep the old function name for backward compatibility but remove report creation
def complete_scan_with_ai_analysis_and_report(scan):
    """Legacy function name - now just calls complete_scan_with_ai_analysis"""
    logger.warning("complete_scan_with_ai_analysis_and_report is deprecated, use complete_scan_with_ai_analysis")
    return complete_scan_with_ai_analysis(scan)

@shared_task
def start_passive_scan_task(scan_id):
    """Celery task to run a passive scan asynchronously"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from scanner.services.passive_scanner import PassiveScanService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Verify this is a passive or mixed scan
        if scan.scan_mode not in ['passive', 'mixed']:
            raise ValueError(f"Cannot run passive scan on scan mode: {scan.scan_mode}")
        
        logger.info(f"Starting passive scan for {scan.target_url} (scan_id: {scan_id})")
        
        # Initialize and run the passive scan (PassiveScanService handles its own status updates)
        scanner = PassiveScanService(scan)
        scanner.run()
        
        return {"status": "success", "scan_id": scan_id, "scan_type": "passive"}
    
    except Exception as e:
        logger.exception(f"Error running passive scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        except Exception as update_error:
            logger.exception(f"Error updating passive scan status: {str(update_error)}")
        
        return {"status": "error", "message": str(e), "scan_type": "passive"}

@shared_task(time_limit=600, soft_time_limit=540)
def start_active_scan_task(scan_id):
    """Celery task to run an active scan asynchronously"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from scanner.services.active_scanner import ActiveScanService
        from compliance.services.compliance_service import ComplianceService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Verify this is an active or mixed scan
        if scan.scan_mode not in ['active', 'mixed']:
            raise ValueError(f"Cannot run active scan on scan mode: {scan.scan_mode}")
        
        logger.info(f"Starting active scan for {scan.target_url} (scan_id: {scan_id})")
        
        # Verify authorization for active scanning using compliance service
        compliance_service = ComplianceService(scan.user)
        can_scan, reason = compliance_service.can_scan_domain(scan.target_url, 'active')
        
        if not can_scan:
            raise ValueError(f"Active scanning not authorized for domain: {reason}")
        
        # Initialize and run the active scan (ActiveScanService handles its own status updates)
        scanner = ActiveScanService(scan, user=scan.user, compliance_mode=scan.compliance_mode)
        scanner.run()
        
        return {"status": "success", "scan_id": scan_id, "scan_type": "active"}
    
    except Exception as e:
        logger.exception(f"Error running active scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        except Exception as update_error:
            logger.exception(f"Error updating active scan status: {str(update_error)}")
        
        return {"status": "error", "message": str(e), "scan_type": "active"}

class MixedScanOrchestrator:
    """Helper class to properly orchestrate mixed scans without duplicates"""
    
    def __init__(self, scan):
        self.scan = scan
        self.passive_results_count = 0
        self.active_results_count = 0
        
        # Define which scan types are passive vs active
        self.passive_scan_types = {
            'headers', 'ssl', 'content', 'csp', 'cookies', 
            'cors', 'server', 'ports'
        }
        self.active_scan_types = {'vulnerabilities'}
    
    def run_mixed_scan(self):
        """Run mixed scan with proper orchestration"""
        logger.info(f"Starting mixed scan orchestration for {self.scan.target_url}")
        
        # Update scan status to in progress
        self.scan.status = 'in_progress'
        self.scan.started_at = timezone.now()
        self.scan.save()
        
        # Separate scan types
        requested_passive = [st for st in self.scan.scan_types if st in self.passive_scan_types]
        requested_active = [st for st in self.scan.scan_types if st in self.active_scan_types]
        
        logger.info(f"Mixed scan breakdown - Passive: {requested_passive}, Active: {requested_active}")
        
        # Phase 1: Run passive scans with limited scope
        if requested_passive:
            self._run_passive_phase(requested_passive)
        
        # Phase 2: Run active scans if authorized
        if requested_active:
            self._run_active_phase(requested_active)
        else:
            logger.info("No active scan types requested")
        
        # Phase 3: Complete the scan
        self._complete_mixed_scan()
    
    def _run_passive_phase(self, passive_types):
        """Run passive scanning phase"""
        try:
            from scanner.services.passive_scanner import PassiveScanService
            
            logger.info(f"Starting passive phase with types: {passive_types}")
            
            # Temporarily modify the scan's scan_types for this phase
            original_scan_types = self.scan.scan_types
            self.scan.scan_types = passive_types
            
            try:
                # Run passive scanner but don't let it auto-complete the scan
                passive_scanner = PassiveScanService(self.scan, auto_complete=False)
                passive_scanner.run()
            finally:
                # Restore original scan types
                self.scan.scan_types = original_scan_types
            
            # Count results from passive phase
            from scanner.models import ScanResult
            self.passive_results_count = ScanResult.objects.filter(
                scan=self.scan,
                category__in=passive_types
            ).count()
            
            logger.info(f"Passive phase completed with {self.passive_results_count} results")
            
        except Exception as e:
            logger.error(f"Error in passive phase: {str(e)}")
            # Continue to active phase even if passive fails
    
    def _run_active_phase(self, active_types):
        """Run active scanning phase"""
        try:
            from scanner.services.active_scanner import ActiveScanService
            from compliance.services.compliance_service import ComplianceService
            from scanner.models import ScanResult
            
            # Check authorization
            compliance_service = ComplianceService(self.scan.user)
            can_scan, reason = compliance_service.can_scan_domain(self.scan.target_url, 'active')
            
            if not can_scan:
                logger.info(f"Skipping active phase - {reason}")
                
                # Add informational result about skipped active scan
                ScanResult.objects.create(
                    scan=self.scan,
                    category='authorization',
                    name='Active Scan Authorization Required',
                    description=f'Active testing was skipped: {reason}',
                    severity='info',
                    details={
                        'reason': 'no_authorization',
                        'domain': self.scan.target_url,
                        'recommendation': 'Request domain authorization to enable active testing',
                        'scan_type': 'mixed',
                        'authorization_reason': reason,
                        'scan_id': str(self.scan.id),
                        'target_url': self.scan.target_url,
                        'found_at': timezone.now().isoformat()
                    }
                )
                return
            
            logger.info(f"Starting active phase with types: {active_types}")
            
            # Temporarily modify the scan's scan_types for this phase
            original_scan_types = self.scan.scan_types
            self.scan.scan_types = active_types
            
            try:
                # Run active scanner with rate limiting skipped for mixed scans
                active_scanner = ActiveScanService(
                    self.scan, 
                    user=self.scan.user, 
                    compliance_mode=getattr(self.scan, 'compliance_mode', 'strict'),
                    auto_complete=False,
                    skip_rate_limiting=True  # Skip rate limiting for mixed scans
                )
                active_scanner.run()
            finally:
                # Restore original scan types
                self.scan.scan_types = original_scan_types
            
            # Count results from active phase
            self.active_results_count = ScanResult.objects.filter(
                scan=self.scan,
                category__in=[f"active_{at}" for at in active_types]  # Active results are prefixed
            ).count()
            
            logger.info(f"Active phase completed with {self.active_results_count} results")
            
        except Exception as e:
            logger.error(f"Error in active phase: {str(e)}")
            # Continue to completion even if active fails
    
    def _complete_mixed_scan(self):
        """Complete the mixed scan properly"""
        try:
            # Refresh scan from database to get latest state
            self.scan.refresh_from_db()
            
            # Only complete if still in progress
            if self.scan.status == 'in_progress':
                logger.info(f"Completing mixed scan {self.scan.id} - Passive results: {self.passive_results_count}, Active results: {self.active_results_count}")
                
                # Use the centralized completion logic
                complete_scan_with_ai_analysis(self.scan)
            else:
                logger.warning(f"Mixed scan {self.scan.id} status is {self.scan.status}, not completing")
                
        except Exception as e:
            logger.exception(f"Error completing mixed scan {self.scan.id}: {str(e)}")
            self.scan.status = 'failed'
            self.scan.error_message = str(e)
            self.scan.completed_at = timezone.now()
            self.scan.save()

@shared_task(time_limit=600, soft_time_limit=540)
def start_mixed_scan_task(scan_id):
    """Celery task to run a mixed scan (passive + active) asynchronously - FINAL VERSION"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Verify this is a mixed scan
        if scan.scan_mode != 'mixed':
            raise ValueError(f"Cannot run mixed scan on scan mode: {scan.scan_mode}")
        
        logger.info(f"Starting mixed scan orchestration for {scan.target_url} (scan_id: {scan_id})")
        
        # Use the orchestrator to properly manage the mixed scan
        orchestrator = MixedScanOrchestrator(scan)
        orchestrator.run_mixed_scan()
        
        return {
            "status": "success", 
            "scan_id": scan_id, 
            "scan_type": "mixed",
            "passive_results": orchestrator.passive_results_count,
            "active_results": orchestrator.active_results_count
        }
    
    except Exception as e:
        logger.exception(f"Error running mixed scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        except Exception as update_error:
            logger.exception(f"Error updating mixed scan status: {str(update_error)}")
        
        return {"status": "error", "message": str(e), "scan_type": "mixed"}

# Legacy task for backward compatibility
@shared_task
def start_scan_task(scan_id):
    """Legacy Celery task - redirects to appropriate scan type"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Redirect to appropriate task based on scan mode
        if scan.scan_mode == 'passive':
            return start_passive_scan_task(scan_id)  # Call directly, don't use .delay()
        elif scan.scan_mode == 'active':
            return start_active_scan_task(scan_id)
        elif scan.scan_mode == 'mixed':
            return start_mixed_scan_task(scan_id)
        else:
            # Default to passive for safety
            logger.warning(f"Unknown scan mode {scan.scan_mode} for scan {scan_id}, defaulting to passive")
            scan.scan_mode = 'passive'
            scan.save()
            return start_passive_scan_task(scan_id)
    
    except Exception as e:
        logger.exception(f"Error in legacy scan task {scan_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task(bind=True, max_retries=3)
def run_ai_analysis_task(self, scan_id):
    """Celery task to run AI analysis on scan results"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from ai_analyzer.services.ai_analysis import AIAnalysisService
        
        logger.info(f"Starting AI analysis for scan {scan_id}")
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Check if scan is completed
        if scan.status != 'completed':
            logger.warning(f"Cannot analyze scan {scan_id} that is not completed. Current status: {scan.status}")
            raise ValueError(f"Cannot analyze scan that is not completed. Current status: {scan.status}")
        
        # Check if AI analysis already exists for this scan
        from ai_analyzer.models import AIAnalysis
        existing_analysis = AIAnalysis.objects.filter(scan_id=str(scan.id)).first()
        
        if existing_analysis:
            logger.info(f"AI analysis already exists for scan {scan_id}, skipping")
            return {"status": "skipped", "scan_id": scan_id, "reason": "Analysis already exists"}
        
        # Run the AI analysis
        analysis_service = AIAnalysisService(scan)
        analysis_service.analyze()
        
        logger.info(f"AI analysis completed successfully for scan {scan_id}")
        return {"status": "success", "scan_id": scan_id}
    
    except Scan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found for AI analysis")
        return {"status": "error", "message": f"Scan {scan_id} not found"}
    
    except Exception as e:
        logger.exception(f"Error running AI analysis for scan {scan_id}: {str(e)}")
        
        # Retry the task with exponential backoff
        if self.request.retries < self.max_retries:
            retry_countdown = 60 * (2 ** self.request.retries)  # 60, 120, 240 seconds
            logger.info(f"Retrying AI analysis for scan {scan_id} in {retry_countdown} seconds (attempt {self.request.retries + 1})")
            raise self.retry(countdown=retry_countdown, exc=e)
        
        return {"status": "error", "message": str(e)}

@shared_task
def cleanup_expired_scans():
    """Clean up old scan data based on retention policies"""
    try:
        from scanner.models import Scan, SecurityAuditLog
        from ai_analyzer.models import AIAnalysis
        from datetime import timedelta
        
        # Delete scans older than 90 days
        cutoff_date = timezone.now() - timedelta(days=90)
        old_scans = Scan.objects.filter(created_at__lt=cutoff_date)
        
        count = old_scans.count()
        old_scans.delete()
        
        # Clean up old AI analyses (they should be deleted with scans due to cascade)
        old_analyses = AIAnalysis.objects.filter(created_at__lt=cutoff_date)
        analyses_count = old_analyses.count()
        old_analyses.delete()
        
        # Clean up old audit logs (keep for 1 year)
        audit_cutoff = timezone.now() - timedelta(days=365)
        old_logs = SecurityAuditLog.objects.filter(timestamp__lt=audit_cutoff)
        
        log_count = old_logs.count()
        old_logs.delete()
        
        logger.info(f"Cleanup completed: removed {count} old scans, {analyses_count} old analyses, and {log_count} old audit logs")
        
        return {
            "status": "success", 
            "scans_deleted": count,
            "analyses_deleted": analyses_count,
            "logs_deleted": log_count
        }
    
    except Exception as e:
        logger.exception(f"Error in cleanup task: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task
def generate_compliance_report(user_id, report_type='weekly'):
    """Generate compliance reports for users or administrators"""
    try:
        from django.contrib.auth import get_user_model
        from scanner.models import Scan, SecurityAuditLog
        from compliance.services.compliance_service import ComplianceService
        from datetime import timedelta
        import json
        
        User = get_user_model()
        user = User.objects.get(id=user_id)
        
        # Determine report period
        end_date = timezone.now()
        if report_type == 'daily':
            start_date = end_date - timedelta(days=1)
        elif report_type == 'weekly':
            start_date = end_date - timedelta(days=7)
        elif report_type == 'monthly':
            start_date = end_date - timedelta(days=30)
        else:
            start_date = end_date - timedelta(days=7)
        
        # Gather compliance data
        scans_in_period = Scan.objects.filter(
            user=user,
            created_at__range=[start_date, end_date]
        )
        
        audit_logs_in_period = SecurityAuditLog.objects.filter(
            user=user,
            timestamp__range=[start_date, end_date]
        )
        
        # Get user's compliance status
        compliance_service = ComplianceService(user)
        compliance_status = compliance_service.get_status()
        
        # Generate report data
        report_data = {
            'user_id': user_id,
            'username': user.username,
            'report_period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'type': report_type
            },
            'compliance_status': {
                'all_agreements_accepted': compliance_status.get('all_agreements_accepted', False),
                'missing_agreements': compliance_status.get('missing_agreements', []),
                'authorized_domains_count': len(compliance_status.get('authorized_domains', [])),
                'can_active_scan': compliance_status.get('can_active_scan', False)
            },
            'scan_summary': {
                'total_scans': scans_in_period.count(),
                'passive_scans': scans_in_period.filter(scan_mode='passive').count(),
                'active_scans': scans_in_period.filter(scan_mode='active').count(),
                'mixed_scans': scans_in_period.filter(scan_mode='mixed').count(),
                'completed_scans': scans_in_period.filter(status='completed').count(),
                'failed_scans': scans_in_period.filter(status='failed').count()
            },
            'compliance_events': {
                'total_events': audit_logs_in_period.count(),
                'scan_initiations': audit_logs_in_period.filter(event_type__endswith='_scan_initiated').count(),
                'compliance_violations': audit_logs_in_period.filter(event_type='compliance_violation').count(),
                'unauthorized_attempts': audit_logs_in_period.filter(event_type='unauthorized_attempt').count(),
                'agreement_acceptances': audit_logs_in_period.filter(event_type='agreement_accepted').count(),
                'domain_requests': audit_logs_in_period.filter(event_type='domain_authorization_requested').count()
            }
        }
        
        # Create a simple report summary
        summary = (
            f"{report_type.title()} compliance report for {user.username}: "
            f"{report_data['scan_summary']['total_scans']} scans, "
            f"{report_data['compliance_events']['total_events']} events, "
            f"Compliance: {'✓' if report_data['compliance_status']['all_agreements_accepted'] else '✗'}"
        )
        
        logger.info(f"Generated compliance report for user {user_id}: {summary}")
        
        return {
            "status": "success", 
            "user_id": user_id,
            "report_data": report_data,
            "summary": summary
        }
    
    except Exception as e:
        logger.exception(f"Error generating compliance report: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task
def generate_pdf_report_task(scan_id, user_id):
    """Celery task to generate PDF report asynchronously (optional for large reports)"""
    try:
        from scanner.models import Scan, ScanResult
        from scanner.services.pdf_report_generator import PDFReportGenerator
        from django.contrib.auth import get_user_model
        import tempfile
        import os
        
        User = get_user_model()
        user = User.objects.get(id=user_id)
        scan = Scan.objects.get(id=scan_id, user=user)
        
        if scan.status != 'completed':
            raise ValueError("Cannot generate PDF for incomplete scan")
        
        logger.info(f"Generating PDF report for scan {scan_id}")
        
        # Get scan results
        results = ScanResult.objects.filter(scan=scan).order_by('severity')
        
        # Generate the PDF report
        report_generator = PDFReportGenerator(scan, results)
        pdf_data = report_generator.generate_pdf()
        
        # For now, just return success - you could extend this to:
        # - Save PDF to file storage (S3, local storage)
        # - Email PDF to user
        # - Store PDF reference in database
        # - etc.
        
        logger.info(f"PDF report generated successfully for scan {scan_id}, size: {len(pdf_data)} bytes")
        
        return {
            "status": "success",
            "scan_id": scan_id,
            "user_id": user_id,
            "pdf_size": len(pdf_data)
        }
        
    except Exception as e:
        logger.exception(f"Error generating PDF report for scan {scan_id}: {str(e)}")
        return {"status": "error", "message": str(e), "scan_id": scan_id}

@shared_task
def clear_domain_rate_limit_task(domain_or_url):
    """Celery task to clear rate limiting for a specific domain"""
    try:
        from urllib.parse import urlparse
        from django.core.cache import cache
        
        # Extract domain from URL if needed
        if domain_or_url.startswith('http'):
            domain = urlparse(domain_or_url).netloc
        else:
            domain = domain_or_url
        
        # Clear the rate limit cache
        cache_key = f"scanner_rate_limit_{domain}"
        cache.delete(cache_key)
        
        logger.info(f"Cleared rate limit cache for domain: {domain}")
        
        return {
            "status": "success",
            "domain": domain,
            "message": f"Rate limit cleared for {domain}"
        }
        
    except Exception as e:
        logger.exception(f"Error clearing rate limit for {domain_or_url}: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task  
def clear_all_rate_limits_task():
    """Celery task to clear all rate limiting (admin only)"""
    try:
        from django.core.cache import cache
        
        # This clears all cache - use with caution
        cache.clear()
        
        logger.info("Cleared all cache including rate limits")
        
        return {
            "status": "success",
            "message": "All rate limits cleared"
        }
        
    except Exception as e:
        logger.exception(f"Error clearing all rate limits: {str(e)}")
        return {"status": "error", "message": str(e)}