# backend/celery_app/tasks.py - Updated with consolidated compliance support

from celery import shared_task
from django.utils import timezone
import logging
import uuid

logger = logging.getLogger(__name__)

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
        
        # Update scan status to completed (if not already updated by scanner)
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
        
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
        
        # Update scan status to completed (if not already updated by scanner)
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
        
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
        
        # Update scan status to completed
        scan.refresh_from_db()
        if scan.status == 'in_progress':
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()
        
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

@shared_task
def run_ai_analysis_task(scan_id):
    """Celery task to run AI analysis on scan results"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from ai_analyzer.services.ai_analysis import AIAnalysisService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Check if scan is completed
        if scan.status != 'completed':
            raise ValueError(f"Cannot analyze scan that is not completed. Current status: {scan.status}")
        
        # Run the AI analysis
        analysis_service = AIAnalysisService(scan)
        analysis_service.analyze()
        
        return {"status": "success", "scan_id": scan_id}
    
    except Exception as e:
        logger.exception(f"Error running AI analysis for scan {scan_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task
def cleanup_expired_scans():
    """Clean up old scan data based on retention policies"""
    try:
        from scanner.models import Scan
        from compliance.models import SecurityAuditLog
        from datetime import timedelta
        
        # Delete scans older than 90 days
        cutoff_date = timezone.now() - timedelta(days=90)
        old_scans = Scan.objects.filter(created_at__lt=cutoff_date)
        
        count = old_scans.count()
        old_scans.delete()
        
        # Clean up old audit logs (keep for 1 year)
        audit_cutoff = timezone.now() - timedelta(days=365)
        old_logs = SecurityAuditLog.objects.filter(timestamp__lt=audit_cutoff)
        
        log_count = old_logs.count()
        old_logs.delete()
        
        logger.info(f"Cleanup completed: removed {count} old scans and {log_count} old audit logs")
        
        return {
            "status": "success", 
            "scans_deleted": count, 
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
        
        # Create a simple report summary since ComplianceReport model might not exist
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
def verify_domain_authorization_task(domain_auth_id):
    """Celery task to verify domain authorization asynchronously"""
    try:
        from compliance.models import DomainAuthorization
        from compliance.services.compliance_service import ComplianceService
        
        # Get the domain authorization
        domain_auth = DomainAuthorization.objects.get(id=domain_auth_id)
        
        # Use the compliance service for verification
        compliance_service = ComplianceService(domain_auth.user)
        
        # Perform basic verification based on verification method
        result = {'success': False, 'error': 'Verification method not implemented'}
        
        if domain_auth.verification_method == 'manual_approval':
            # Manual approval - just mark as needing admin review
            result = {
                'success': True, 
                'message': 'Manual approval required - notified administrators',
                'verification_method': 'manual_approval'
            }
            logger.info(f"Domain {domain_auth.domain} marked for manual approval")
            
        elif domain_auth.verification_method == 'dns_txt':
            # For now, just log that DNS verification would happen here
            # In a full implementation, you'd check for the TXT record
            result = {
                'success': False,
                'error': 'DNS TXT verification not yet implemented',
                'verification_method': 'dns_txt',
                'instructions': f'Add TXT record: {domain_auth.verification_token}'
            }
            logger.info(f"DNS TXT verification requested for {domain_auth.domain}")
            
        elif domain_auth.verification_method == 'file_upload':
            # File upload verification would be implemented here
            result = {
                'success': False,
                'error': 'File upload verification not yet implemented',
                'verification_method': 'file_upload'
            }
            logger.info(f"File upload verification requested for {domain_auth.domain}")
            
        elif domain_auth.verification_method == 'email_verification':
            # Email verification would be implemented here
            result = {
                'success': False,
                'error': 'Email verification not yet implemented',
                'verification_method': 'email_verification'
            }
            logger.info(f"Email verification requested for {domain_auth.domain}")
        
        if result['success']:
            logger.info(f"Domain verification successful for {domain_auth.domain}")
            return {
                "status": "success", 
                "domain_auth_id": domain_auth_id,
                "domain": domain_auth.domain,
                "verification_result": result
            }
        else:
            logger.warning(f"Domain verification failed for {domain_auth.domain}: {result.get('error')}")
            return {
                "status": "failed", 
                "domain_auth_id": domain_auth_id,
                "domain": domain_auth.domain,
                "error": result.get('error'),
                "verification_result": result
            }
    
    except Exception as e:
        logger.exception(f"Error verifying domain authorization {domain_auth_id}: {str(e)}")
        return {"status": "error", "message": str(e)}

@shared_task
def send_compliance_notifications():
    """Send notifications for compliance-related events"""
    try:
        from compliance.models import DomainAuthorization
        from datetime import timedelta
        from django.core.mail import send_mail
        from django.conf import settings
        
        notifications_sent = 0
        
        # Check for expiring domain authorizations (30 days warning)
        warning_date = timezone.now() + timedelta(days=30)
        expiring_auths = DomainAuthorization.objects.filter(
            status='verified',
            is_active=True,
            expires_at__lte=warning_date,
            expires_at__gt=timezone.now()
        ).select_related('user')
        
        for auth in expiring_auths:
            try:
                # Simple email notification for expiring domains
                if auth.user and auth.user.email:
                    days_until_expiry = (auth.expires_at - timezone.now()).days
                    
                    send_mail(
                        subject=f'Domain Authorization Expiring: {auth.domain}',
                        message=f'''
Your domain authorization for {auth.domain} will expire in {days_until_expiry} days.

Expiration Date: {auth.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

Please renew your authorization before it expires to continue active scanning.

Best regards,
Security Scanner Team
                        '''.strip(),
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                        recipient_list=[auth.user.email],
                        fail_silently=True
                    )
                    notifications_sent += 1
                    logger.info(f"Sent expiration warning email for domain {auth.domain} to {auth.user.email}")
            except Exception as e:
                logger.error(f"Failed to send expiration warning for {auth.domain}: {str(e)}")
        
        # Check for pending authorization requests (remind after 7 days)
        reminder_date = timezone.now() - timedelta(days=7)
        pending_auths = DomainAuthorization.objects.filter(
            status='pending',
            created_at__lte=reminder_date
        ).select_related('user')
        
        for auth in pending_auths:
            try:
                # Simple email notification for pending requests
                if auth.user and auth.user.email:
                    days_pending = (timezone.now() - auth.created_at).days
                    
                    send_mail(
                        subject=f'Domain Authorization Pending: {auth.domain}',
                        message=f'''
Your domain authorization request for {auth.domain} has been pending for {days_pending} days.

Requested Date: {auth.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
Verification Method: {auth.verification_method}

Please complete the verification process or contact support if you need assistance.

Best regards,
Security Scanner Team
                        '''.strip(),
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                        recipient_list=[auth.user.email],
                        fail_silently=True
                    )
                    notifications_sent += 1
                    logger.info(f"Sent pending reminder email for domain {auth.domain} to {auth.user.email}")
            except Exception as e:
                logger.error(f"Failed to send pending reminder for {auth.domain}: {str(e)}")
        
        return {
            "status": "success",
            "notifications_sent": notifications_sent,
            "expiring_count": expiring_auths.count(),
            "pending_count": pending_auths.count()
        }
    
    except Exception as e:
        logger.exception(f"Error sending compliance notifications: {str(e)}")
        return {"status": "error", "message": str(e)}