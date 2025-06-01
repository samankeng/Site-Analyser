# backend/scanner/models.py - Cleaned up version without domain authorization

from django.db import models
from django.conf import settings
import uuid

from django.utils import timezone
class Scan(models.Model):
    """Model for security scan requests with passive/active support"""
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    
    SCAN_MODE_CHOICES = (
        ('passive', 'Passive Scan Only'),
        ('active', 'Active Scan (Requires Authorization)'),
        ('mixed', 'Mixed (Passive + Active)'),
    )
    
    COMPLIANCE_MODE_CHOICES = (
        ('strict', 'Strict'),
        ('moderate', 'Moderate'),
        ('permissive', 'Permissive'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target_url = models.URLField(max_length=255)
    scan_types = models.JSONField(default=list)  # List of scan types to perform
    
    # New field to specify scan mode
    scan_mode = models.CharField(
        max_length=20, 
        choices=SCAN_MODE_CHOICES, 
        default='passive',
        help_text='Type of scan to perform'
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    # Compliance fields
    compliance_mode = models.CharField(
        max_length=20, 
        choices=COMPLIANCE_MODE_CHOICES,
        default='strict',
        help_text='Compliance mode for the scan'
    )
    
    # Reference to compliance app's domain authorization
    authorization = models.ForeignKey(
        'compliance.DomainAuthorization',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scans',
        help_text='Domain authorization required for active scanning'
    )
    
    terms_accepted = models.BooleanField(
        default=False,
        help_text='Whether user accepted terms of service'
    )
    
    terms_accepted_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text='When terms were accepted'
    )
    
    terms_ip_address = models.GenericIPAddressField(
        null=True, 
        blank=True,
        help_text='IP address when terms were accepted'
    )
    
    # Compliance tracking
    requests_made = models.IntegerField(
        default=0,
        help_text='Number of requests made during scan'
    )
    
    pages_scanned = models.IntegerField(
        default=0,
        help_text='Number of pages scanned'
    )
    
    compliance_violations = models.JSONField(
        default=list,
        blank=True,
        help_text='List of compliance violations during scan'
    )
    
    # Authorization check
    authorization_required = models.BooleanField(
        default=False,
        help_text='Whether this scan requires explicit authorization'
    )
    
    def __str__(self):
        return f"Scan {self.id} - {self.target_url} ({self.status}) - {self.scan_mode}"
    
    def requires_authorization(self):
        """Check if this scan requires authorization based on scan mode and target"""
        from urllib.parse import urlparse
        
        # Passive scans never require authorization
        if self.scan_mode == 'passive':
            return False
        
        # Active and mixed scans require authorization (except for dev domains)
        if self.scan_mode in ['active', 'mixed']:
            try:
                parsed_url = urlparse(self.target_url)
                domain = parsed_url.netloc.lower()
                
                # Remove port numbers if present
                if ':' in domain:
                    domain = domain.split(':')[0]
                
                # Check if it's in PreauthorizedDomain model
                from compliance.models import PreauthorizedDomain
                if PreauthorizedDomain.is_preauthorized(self.target_url):
                    return False
                
                # All other domains require authorization for active scanning
                return True
                
            except Exception as e:
                # If we can't parse the URL, err on the side of caution
                return True
        
        # Default to not requiring authorization
        return False

    def is_authorized(self):
        """Check if this scan is properly authorized"""
        if not self.authorization:
            return False
        
        # For DomainAuthorization, check status and expiry
        if self.authorization.status != 'verified' or not self.authorization.is_active:
            return False
            
        # Check if expired
        if self.authorization.expires_at and timezone.now() > self.authorization.expires_at:
            return False
            
        return True

class ScanResult(models.Model):
    """Model for scan results"""
    SEVERITY_CHOICES = (
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    category = models.CharField(max_length=50)  # e.g., 'headers', 'ssl', 'content', 'vulnerability'
    name = models.CharField(max_length=100)  # Name of finding
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    details = models.JSONField(default=dict)  # Detailed findings in JSON format
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.category} - {self.name} ({self.severity})"

class SecurityAuditLog(models.Model):
    """Security audit log for compliance and monitoring"""
    
    EVENT_TYPES = (
        ('scan_initiated', 'Scan Initiated'),
        ('scan_completed', 'Scan Completed'),
        ('scan_cancelled', 'Scan Cancelled'),
        ('compliance_violation', 'Compliance Violation'),
        ('unauthorized_attempt', 'Unauthorized Scan Attempt'),
        ('rate_limit_exceeded', 'Rate Limit Exceeded'),
        ('suspicious_activity', 'Suspicious Activity'),
        ('vulnerability_found', 'Vulnerability Found'),
        ('admin_action', 'Admin Action'),
        ('active_scan_initiated', 'Active Scan Initiated'),
        ('passive_scan_initiated', 'Passive Scan Initiated'),
    )
    
    SEVERITY_LEVELS = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    )
    
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='low')
    
    # Event details
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='audit_logs'
    )
    
    # Network information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Scan information
    target_domain = models.CharField(max_length=255, blank=True)
    scan_id = models.UUIDField(null=True, blank=True)
    scan_mode = models.CharField(max_length=20, blank=True)  # passive, active, mixed
    compliance_mode = models.CharField(max_length=20, blank=True)
    
    # Event data
    event_data = models.JSONField(default=dict)
    message = models.TextField()
    
    # Administrative fields
    reviewed = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_audit_logs'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['target_domain', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['scan_mode', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.event_type} - {self.severity}"

class ComplianceReport(models.Model):
    """Generate compliance reports for auditing purposes"""
    
    REPORT_TYPES = (
        ('daily', 'Daily Activity Report'),
        ('weekly', 'Weekly Summary Report'),
        ('monthly', 'Monthly Compliance Report'),
        ('incident', 'Security Incident Report'),
        ('audit', 'Compliance Audit Report'),
    )
    
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='generated_reports'
    )
    
    # Report period
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    # Report data
    report_data = models.JSONField(default=dict)
    summary = models.TextField()
    
    # Report file
    report_file = models.FileField(upload_to='compliance_reports/', blank=True, null=True)
    
    class Meta:
        ordering = ['-generated_at']
    
    def __str__(self):
        return f"{self.report_type} - {self.period_start.date()} to {self.period_end.date()}"