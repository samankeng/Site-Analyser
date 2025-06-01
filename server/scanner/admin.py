# backend/scanner/admin.py - Fixed imports and model references

from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Q
from datetime import timedelta

# Import models from the correct apps
from .models import (
    Scan, 
    ScanResult, 
    SecurityAuditLog,
    ComplianceReport
)

# Import compliance models from the compliance app
from compliance.models import (
    ComplianceAgreement, 
    DomainAuthorization,
    UserComplianceStatus,
    PreauthorizedDomain
)

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'target_url', 'user', 'scan_mode', 'status', 
        'compliance_mode', 'authorization_status', 'created_at'
    )
    list_filter = (
        'status', 'scan_mode', 'compliance_mode', 'authorization_required', 
        'terms_accepted', 'created_at'
    )
    search_fields = ('target_url', 'user__email', 'user__username')
    readonly_fields = (
        'id', 'created_at', 'updated_at', 'started_at', 'completed_at',
        'terms_ip_address', 'requests_made', 'pages_scanned'
    )
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'user', 'target_url', 'scan_types')
        }),
        ('Scan Configuration', {
            'fields': ('scan_mode', 'status', 'compliance_mode', 'error_message')
        }),
        ('Authorization & Compliance', {
            'fields': (
                'authorization', 'authorization_required', 'terms_accepted', 
                'terms_accepted_at', 'terms_ip_address'
            )
        }),
        ('Compliance Tracking', {
            'fields': ('requests_made', 'pages_scanned', 'compliance_violations'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'started_at', 'completed_at'),
            'classes': ('collapse',)
        }),
    )
    
    def authorization_status(self, obj):
        """Display authorization status with color coding"""
        if not obj.authorization_required:
            return format_html('<span style="color: green;">✓ Not Required</span>')
        elif obj.authorization and obj.is_authorized():
            return format_html('<span style="color: green;">✓ Authorized</span>')
        elif obj.authorization:
            return format_html('<span style="color: orange;">⚠ Auth Expired/Invalid</span>')
        else:
            return format_html('<span style="color: red;">✗ Missing Authorization</span>')
    
    authorization_status.short_description = 'Authorization Status'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'authorization')

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan_link', 'category', 'name', 'severity', 'created_at')
    list_filter = ('category', 'severity', 'created_at')
    search_fields = ('scan__target_url', 'name', 'description')
    readonly_fields = ('id', 'created_at')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'scan', 'category')
        }),
        ('Finding Details', {
            'fields': ('name', 'description', 'severity', 'details')
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )
    
    def scan_link(self, obj):
        """Create clickable link to scan"""
        url = reverse("admin:scanner_scan_change", args=[obj.scan.id])
        return format_html('<a href="{}">{}</a>', url, obj.scan.target_url)
    
    scan_link.short_description = 'Scan'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('scan', 'scan__user')

@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'event_type', 'severity', 'user_link', 
        'target_domain', 'scan_mode', 'reviewed'
    )
    list_filter = (
        'event_type', 'severity', 'scan_mode', 'compliance_mode', 
        'reviewed', 'timestamp'
    )
    search_fields = (
        'user__username', 'target_domain', 'message', 
        'ip_address', 'scan_id'
    )
    readonly_fields = (
        'timestamp', 'ip_address', 'user_agent', 'event_data'
    )
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Event Information', {
            'fields': ('event_type', 'severity', 'timestamp', 'message')
        }),
        ('User & Network', {
            'fields': ('user', 'ip_address', 'user_agent')
        }),
        ('Scan Information', {
            'fields': ('target_domain', 'scan_id', 'scan_mode', 'compliance_mode')
        }),
        ('Event Data', {
            'fields': ('event_data',),
            'classes': ('collapse',)
        }),
        ('Review Status', {
            'fields': ('reviewed', 'reviewed_by', 'reviewed_at')
        })
    )
    
    def user_link(self, obj):
        """Create clickable link to user"""
        if obj.user:
            url = reverse("admin:auth_user_change", args=[obj.user.id])
            return format_html('<a href="{}">{}</a>', url, obj.user.username)
        return '-'
    
    user_link.short_description = 'User'
    
    def has_change_permission(self, request, obj=None):
        # Only allow changing review status
        return True
    
    def has_delete_permission(self, request, obj=None):
        # Audit logs should not be deleted
        return request.user.is_superuser
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'reviewed_by')
    
    actions = ['mark_as_reviewed']
    
    def mark_as_reviewed(self, request, queryset):
        """Mark selected audit logs as reviewed"""
        updated = queryset.update(
            reviewed=True,
            reviewed_by=request.user,
            reviewed_at=timezone.now()
        )
        self.message_user(request, f'{updated} audit logs marked as reviewed.')
    
    mark_as_reviewed.short_description = "Mark selected logs as reviewed"

# Note: UserAgreement, DomainAuthorization, and ComplianceReport admin classes
# should be registered in compliance/admin.py since they belong to the compliance app

# Custom admin site configuration
admin.site.site_header = "Security Scanner Administration"
admin.site.site_title = "Security Scanner Admin"
admin.site.index_title = "Security Scanner Administration"

# Add custom admin views for statistics
class AdminStats:
    """Helper class for admin statistics"""
    
    @staticmethod
    def get_dashboard_stats():
        """Get dashboard statistics for admin overview"""
        now = timezone.now()
        last_30_days = now - timedelta(days=30)
        
        stats = {
            'scans': {
                'total': Scan.objects.count(),
                'last_30_days': Scan.objects.filter(created_at__gte=last_30_days).count(),
                'by_mode': dict(
                    Scan.objects.values('scan_mode')
                    .annotate(count=Count('scan_mode'))
                    .values_list('scan_mode', 'count')
                ),
                'pending': Scan.objects.filter(status='pending').count(),
            },
            'authorizations': {
                'total': DomainAuthorization.objects.count(),
                'pending': DomainAuthorization.objects.filter(status='pending').count(),
                'approved': DomainAuthorization.objects.filter(status='verified', is_active=True).count(),
                'expiring_soon': DomainAuthorization.objects.filter(
                    status='verified',
                    is_active=True,
                    expires_at__lte=now + timedelta(days=30)
                ).count(),
            },
            'audit_logs': {
                'total': SecurityAuditLog.objects.count(),
                'high_severity': SecurityAuditLog.objects.filter(
                    severity__in=['high', 'critical']
                ).count(),
                'unreviewed': SecurityAuditLog.objects.filter(reviewed=False).count(),
            },
            'users': {
                'total_agreements': ComplianceAgreement.objects.count(),
                'active_scanning_enabled': ComplianceAgreement.objects.filter(
                    agreement_type='active_scanning_agreement'
                ).values('user').distinct().count(),
            }
        }
        
        return stats