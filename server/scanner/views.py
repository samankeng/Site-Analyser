# backend/scanner/views.py - Updated to use only PDF reports

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import HttpResponse
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from urllib.parse import urlparse
from django.conf import settings
from .models import Scan, ScanResult, SecurityAuditLog
from .serializers import (
    ScanSerializer, ScanCreateSerializer, ScanResultSerializer,
    SecurityAuditLogSerializer
)
# Import compliance service from compliance app
from compliance.services.compliance_service import ComplianceService
from celery_app.tasks import start_passive_scan_task, start_active_scan_task
from .services.pdf_report_generator import PDFReportGenerator

import logging

logger = logging.getLogger(__name__)

class ScanViewSet(viewsets.ModelViewSet):
    """Enhanced scan viewset with passive/active scan support"""
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user).order_by('-created_at')
    
    def get_serializer_class(self):
        if self.action == 'create':
            return ScanCreateSerializer
        return self.serializer_class
    
    def perform_create(self, serializer):
        # Get scan mode from request data
        scan_mode = serializer.validated_data.get('scan_mode', 'passive')
        target_url = serializer.validated_data['target_url']
        domain = urlparse(target_url).netloc
        
        # Use compliance service to check authorization
        compliance_service = ComplianceService(self.request.user)
        
        # Check if user can perform this type of scan
        can_scan, reason = compliance_service.can_scan_domain(target_url, scan_mode)
        if not can_scan:
            raise ValidationError({
                'scan_mode': f"Cannot perform {scan_mode} scan: {reason}",
                'domain': domain,
                'required_agreements': compliance_service.get_missing_agreements()
            })
        
        # Get authorization if needed
        authorization = None
        if scan_mode in ['active', 'mixed']:
            authorization = compliance_service.get_domain_authorization(domain)
        
        # Determine compliance mode
        compliance_mode = 'strict' if scan_mode == 'passive' else 'moderate'
        
        # Create the scan
        scan = serializer.save(
            user=self.request.user,
            scan_mode=scan_mode,
            compliance_mode=compliance_mode,
            authorization=authorization,
            terms_accepted=True,
            terms_accepted_at=timezone.now(),
            terms_ip_address=self._get_client_ip(self.request),
            authorization_required=scan_mode in ['active', 'mixed'] and not compliance_service.is_preauthorized_domain(target_url)
        )
        
        # Log scan initiation with scan mode
        SecurityAuditLog.objects.create(
            event_type=f'{scan_mode}_scan_initiated',
            severity='low',
            user=self.request.user,
            ip_address=self._get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            target_domain=domain,
            scan_id=scan.id,
            scan_mode=scan_mode,
            compliance_mode=compliance_mode,
            message=f'{scan_mode.title()} security scan initiated for {domain}',
            event_data={
                'target_url': target_url,
                'scan_types': scan.scan_types,
                'scan_mode': scan_mode,
                'compliance_mode': compliance_mode,
                'is_preauthorized': compliance_service.is_preauthorized_domain(target_url),
                'authorization_required': scan.authorization_required
            }
        )
        
        # Trigger the appropriate scan task based on scan mode
        if scan_mode == 'passive':
            start_passive_scan_task.delay(str(scan.id))
        elif scan_mode == 'active':
            start_active_scan_task.delay(str(scan.id))
        elif scan_mode == 'mixed':
            # Import mixed scan task if it exists
            try:
                from celery_app.tasks import start_mixed_scan_task
                start_mixed_scan_task.delay(str(scan.id))
            except ImportError:
                # Fallback to active scan if mixed isn't implemented yet
                start_active_scan_task.delay(str(scan.id))
        
        return scan
    
    @action(detail=True, methods=['get'])
    def results(self, request, pk=None):
        """Get scan results for a specific scan"""
        try:
            scan = self.get_object()
            results = ScanResult.objects.filter(scan=scan).order_by('-created_at')
            
            # Basic pagination
            page_size = int(request.query_params.get('page_size', 50))
            page = int(request.query_params.get('page', 1))
            start = (page - 1) * page_size
            end = start + page_size
            
            paginated_results = results[start:end]
            serializer = ScanResultSerializer(paginated_results, many=True)
            
            return Response({
                'count': results.count(),
                'results': serializer.data,
                'page': page,
                'page_size': page_size,
                'total_pages': (results.count() + page_size - 1) // page_size
            })
            
        except Exception as e:
            logger.exception(f"Error getting results for scan {pk}: {str(e)}")
            return Response(
                {'detail': f'Error getting results: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def pdf_report(self, request, pk=None):
        """Generate a comprehensive PDF report for a scan"""
        scan = self.get_object()
        
        if scan.status != 'completed':
            return Response(
                {'error': 'Cannot generate report for incomplete scan'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get scan results
            results = ScanResult.objects.filter(scan=scan).order_by('severity')
            
            # Generate the PDF report
            report_generator = PDFReportGenerator(scan, results)
            pdf_data = report_generator.generate_pdf()
            
            # Log PDF generation
            SecurityAuditLog.objects.create(
                event_type='report_generated',
                severity='low',
                user=request.user,
                ip_address=self._get_client_ip(request),
                scan_id=scan.id,
                message=f'PDF report generated for {scan.scan_mode} scan of {scan.target_url}',
                event_data={
                    'scan_mode': scan.scan_mode,
                    'results_count': results.count(),
                    'report_type': 'pdf'
                }
            )
            
            # Create the HTTP response with PDF content
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="security-scan-{scan.scan_mode}-{scan.id}.pdf"'
            response.write(pdf_data)
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating PDF for scan {scan.id}: {str(e)}")
            return Response(
                {'error': f'Failed to generate PDF report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def scan_modes(self, request):
        """Get available scan modes and their descriptions"""
        scan_modes = {
            'passive': {
                'name': 'Passive Scan',
                'description': 'Safe, non-intrusive scanning that can be performed on any website',
                'requirements': [
                    'Accept Terms of Service',
                    'Accept Privacy Policy',
                    'Accept Responsible Disclosure Agreement'
                ],
                'capabilities': [
                    'HTTP header analysis',
                    'SSL/TLS configuration check',
                    'Content analysis',
                    'Cookie security review',
                    'Server information gathering',
                    'Public file exposure check'
                ],
                'authorization_required': False,
                'legal_risk': 'Very Low',
                'recommended_for': 'General security assessment, educational purposes'
            },
            'active': {
                'name': 'Active Scan',
                'description': 'Intrusive testing that may trigger security alerts - requires explicit authorization',
                'requirements': [
                    'Accept all passive scan agreements',
                    'Accept Active Scanning Legal Agreement',
                    'Provide domain authorization',
                    'Demonstrate ownership or written permission'
                ],
                'capabilities': [
                    'All passive scan capabilities',
                    'SQL injection testing',
                    'Cross-site scripting (XSS) testing',
                    'Directory traversal testing',
                    'Authentication bypass testing',
                    'Command injection testing (limited)'
                ],
                'authorization_required': True,
                'legal_risk': 'High',
                'recommended_for': 'Authorized penetration testing, security audits of owned systems'
            },
            'mixed': {
                'name': 'Mixed Scan',
                'description': 'Combines passive and active testing with intelligent authorization checks',
                'requirements': [
                    'Same as active scan requirements',
                    'Domain-specific authorization may be required'
                ],
                'capabilities': [
                    'Automatic mode selection per test',
                    'Passive tests for all targets',
                    'Active tests only for authorized domains',
                    'Compliance-aware testing'
                ],
                'authorization_required': 'Conditional',
                'legal_risk': 'Medium',
                'recommended_for': 'Comprehensive security assessment with proper authorization'
            }
        }
        
        return Response(scan_modes)
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status in ['pending', 'in_progress']:
            scan.status = 'failed'
            scan.error_message = 'Scan cancelled by user'
            scan.save()
            
            # Log cancellation with scan mode
            SecurityAuditLog.objects.create(
                event_type='scan_cancelled',
                severity='low',
                user=request.user,
                ip_address=self._get_client_ip(request),
                scan_id=scan.id,
                scan_mode=scan.scan_mode,
                message=f'{scan.scan_mode.title()} scan cancelled by user for {scan.target_url}'
            )
            
            return Response({'message': 'Scan cancelled'}, status=status.HTTP_200_OK)
        
        return Response(
            {'error': 'Cannot cancel scan with status: ' + scan.status}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=False, methods=['delete'])
    def history(self, request):
        """Delete all scan history for the current user"""
        try:
            user_scans = self.get_queryset()
            count = user_scans.count()
            
            if count > 0:
                # Log bulk deletion
                SecurityAuditLog.objects.create(
                    event_type='admin_action',
                    severity='medium',
                    user=request.user,
                    ip_address=self._get_client_ip(request),
                    message=f'User deleted {count} scans from history',
                    event_data={'deleted_count': count}
                )
                
                result = user_scans.delete()
                deleted_count = result[0] if isinstance(result, tuple) and len(result) > 0 else count
                
                return Response({
                    'success': True,
                    'message': f'Successfully deleted {deleted_count} scans and related data.',
                    'count': deleted_count
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': True,
                    'message': 'No scans found to delete.',
                    'count': 0
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error deleting scan history: {str(e)}")
            
            # Log error
            SecurityAuditLog.objects.create(
                event_type='admin_action',
                severity='high',
                user=request.user,
                ip_address=self._get_client_ip(request),
                message=f'Error deleting scan history: {str(e)}',
                event_data={'error': str(e)}
            )
            
            return Response({
                'success': False,
                'error': f'Failed to delete scan history: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['get'])
    def compliance_report(self, request, pk=None):
        """Generate compliance report for a scan"""
        scan = self.get_object()
        
        # Get scan results
        results = ScanResult.objects.filter(scan=scan)
        
        # Generate compliance report using compliance service
        service = ComplianceService(request.user)
        report_data = service.generate_scan_compliance_report(scan, results)
        
        # Add scan mode specific information
        report_data['scan_mode'] = scan.scan_mode
        report_data['authorization_status'] = {
            'required': scan.requires_authorization(),
            'authorized': scan.is_authorized(),
            'authorization_type': getattr(scan.authorization, 'verification_method', None) if scan.authorization else None
        }
        
        return Response(report_data)
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get scan statistics for the current user"""
        try:
            user_scans = self.get_queryset()
            
            # Count scans by status
            status_counts = {
                'total': user_scans.count(),
                'completed': user_scans.filter(status='completed').count(),
                'in_progress': user_scans.filter(status='in_progress').count(),
                'pending': user_scans.filter(status='pending').count(),
                'failed': user_scans.filter(status='failed').count(),
            }
            
            # Count scans by mode
            mode_counts = {
                'passive': user_scans.filter(scan_mode='passive').count(),
                'active': user_scans.filter(scan_mode='active').count(),
                'mixed': user_scans.filter(scan_mode='mixed').count(),
            }
            
            # Get recent scans
            recent_scans = user_scans[:5]
            recent_scans_data = ScanSerializer(recent_scans, many=True).data
            
            return Response({
                'status_counts': status_counts,
                'mode_counts': mode_counts,
                'recent_scans': recent_scans_data,
            })
            
        except Exception as e:
            logger.exception(f"Error getting scan statistics: {str(e)}")
            return Response(
                {'detail': f'Error getting statistics: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ScanResultViewSet(viewsets.ReadOnlyModelViewSet):
    """Viewset for scan result operations (read-only)"""
    serializer_class = ScanResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Filter results by scan if scan_id is provided in URL
        scan_id = self.kwargs.get('scan_id')
        if scan_id:
            scan = Scan.objects.filter(id=scan_id, user=self.request.user).first()
            if scan:
                return ScanResult.objects.filter(scan=scan).order_by('-created_at')
            return ScanResult.objects.none()
        return ScanResult.objects.filter(scan__user=self.request.user).order_by('-created_at')


class SecurityAuditViewSet(viewsets.ReadOnlyModelViewSet):
    """Security audit log viewing (admin only)"""
    serializer_class = SecurityAuditLogSerializer
    permission_classes = [permissions.IsAdminUser]
    
    def get_queryset(self):
        queryset = SecurityAuditLog.objects.all()
        
        # Filter by event type
        event_type = self.request.query_params.get('event_type')
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')  
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by domain
        domain = self.request.query_params.get('domain')
        if domain:
            queryset = queryset.filter(target_domain__icontains=domain)
        
        # Date range filtering
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        if date_from:
            queryset = queryset.filter(timestamp__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__lte=date_to)
        
        return queryset.order_by('-timestamp')
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get audit log statistics"""
        from django.db.models import Count
        from datetime import datetime, timedelta
        
        # Get statistics for the last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        stats = {
            'total_events': SecurityAuditLog.objects.filter(timestamp__gte=thirty_days_ago).count(),
            'events_by_type': dict(
                SecurityAuditLog.objects.filter(timestamp__gte=thirty_days_ago)
                .values('event_type')
                .annotate(count=Count('event_type'))
                .values_list('event_type', 'count')
            ),
            'events_by_severity': dict(
                SecurityAuditLog.objects.filter(timestamp__gte=thirty_days_ago)
                .values('severity')
                .annotate(count=Count('severity'))
                .values_list('severity', 'count')
            ),
            'high_severity_count': SecurityAuditLog.objects.filter(
                timestamp__gte=thirty_days_ago,
                severity__in=['high', 'critical']
            ).count(),
            'unreviewed_count': SecurityAuditLog.objects.filter(
                reviewed=False,
                severity__in=['medium', 'high', 'critical']
            ).count()
        }
        
        return Response(stats)
    
    @action(detail=True, methods=['post'])
    def mark_reviewed(self, request, pk=None):
        """Mark an audit log entry as reviewed"""
        audit_log = self.get_object()
        audit_log.reviewed = True
        audit_log.reviewed_by = request.user
        audit_log.reviewed_at = timezone.now()
        audit_log.save()
        
        return Response({'message': 'Audit log marked as reviewed'})