# backend/celery_app/tasks.py - Add automatic AI analysis triggering

from celery import shared_task
from django.utils import timezone
from django.conf import settings
import logging
import uuid

logger = logging.getLogger(__name__)

def complete_scan_with_ai_analysis(scan):
    """Helper function to complete scan and trigger AI analysis"""
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
        
        # Update scan status to in progress
        scan.status = 'in_progress'
        scan.started_at = timezone.now()
        scan.save()
        
        # Initialize and run the passive scan
        scanner = PassiveScanService(scan)
        scanner.run()
        
        # Complete scan and trigger AI analysis
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            complete_scan_with_ai_analysis(scan)
        
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

@shared_task
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
        
        # Verify authorization for active scanning using compliance service
        compliance_service = ComplianceService(scan.user)
        auth_check = compliance_service.check_url_authorization(scan.target_url)
        
        if not auth_check.get('scan_capabilities', {}).get('active_enabled', False):
            raise ValueError(f"Active scanning not authorized for domain: {auth_check.get('reason', 'No authorization')}")
        
        # Update scan status to in progress
        scan.status = 'in_progress'
        scan.started_at = timezone.now()
        scan.save()
        
        # Initialize and run the active scan
        scanner = ActiveScanService(scan, user=scan.user, compliance_mode=scan.compliance_mode)
        scanner.run()
        
        # Complete scan and trigger AI analysis
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            complete_scan_with_ai_analysis(scan)
        
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

@shared_task
def start_mixed_scan_task(scan_id):
    """Celery task to run a mixed scan (passive + active) asynchronously"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan, ScanResult
        from scanner.services.passive_scanner import PassiveScanService
        from scanner.services.active_scanner import ActiveScanService
        from compliance.services.compliance_service import ComplianceService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Verify this is a mixed scan
        if scan.scan_mode != 'mixed':
            raise ValueError(f"Cannot run mixed scan on scan mode: {scan.scan_mode}")
        
        # Update scan status to in progress
        scan.status = 'in_progress'
        scan.started_at = timezone.now()
        scan.save()
        
        # Run passive scan first (always safe)
        logger.info(f"Starting passive phase of mixed scan {scan_id}")
        passive_scanner = PassiveScanService(scan)
        passive_scanner.run()
        
        # Check authorization for active scanning using compliance service
        compliance_service = ComplianceService(scan.user)
        auth_check = compliance_service.check_url_authorization(scan.target_url)
        
        if auth_check.get('scan_capabilities', {}).get('active_enabled', False):
            logger.info(f"Starting active phase of mixed scan {scan_id}")
            active_scanner = ActiveScanService(scan, user=scan.user, compliance_mode=scan.compliance_mode)
            active_scanner.run()
        else:
            logger.info(f"Skipping active phase of mixed scan {scan_id} - no authorization")
            
            # Add a result explaining why active scan was skipped
            ScanResult.objects.create(
                scan=scan,
                category='authorization',
                name='Active Scan Skipped',
                description='Active testing was skipped due to lack of authorization for this domain',
                severity='info',
                details={
                    'reason': 'no_authorization',
                    'domain': scan.target_url,
                    'recommendation': 'Request domain authorization to enable active testing',
                    'scan_type': 'mixed',
                    'auth_check_result': auth_check
                }
            )
        
        # Complete scan and trigger AI analysis
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            complete_scan_with_ai_analysis(scan)
        
        return {"status": "success", "scan_id": scan_id, "scan_type": "mixed"}
    
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
            return start_passive_scan_task.delay(scan_id)
        elif scan.scan_mode == 'active':
            return start_active_scan_task.delay(scan_id)
        elif scan.scan_mode == 'mixed':
            return start_mixed_scan_task.delay(scan_id)
        else:
            # Default to passive for safety
            logger.warning(f"Unknown scan mode {scan.scan_mode} for scan {scan_id}, defaulting to passive")
            scan.scan_mode = 'passive'
            scan.save()
            return start_passive_scan_task.delay(scan_id)
    
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
        from scanner.models import Scan
        from compliance.models import SecurityAuditLog
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

# Rest of the tasks remain the same...
@shared_task
def generate_compliance_report(user_id, report_type='weekly'):
    """Generate compliance reports for users or administrators"""
    try:
        from django.contrib.auth import get_user_model
        from scanner.models import Scan
        from compliance.models import SecurityAuditLog, LegalAgreement
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