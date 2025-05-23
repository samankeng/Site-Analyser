from django.db import models
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

User = get_user_model()

class Report(models.Model):
    """Model for storing security scan reports"""
    
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        IN_PROGRESS = 'in_progress', _('In Progress')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')
    
    class SeverityLevel(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFO = 'info', _('Informational')
        NONE = 'none', _('None')
    
    # Basic information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    name = models.CharField(max_length=255, blank=True, null=True)
    target_url = models.URLField(max_length=255)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
    # Scan details
    scan_types = models.JSONField(default=list)  # List of scan types performed
    highest_severity = models.CharField(
        max_length=20,
        choices=SeverityLevel.choices,
        default=SeverityLevel.NONE
    )
    findings_summary = models.JSONField(default=dict)  # Summary of findings by severity
    
    # Results storage
    results = models.JSONField(default=dict)  # Detailed scan results
    notes = models.TextField(blank=True, null=True)  # User notes
    error_message = models.TextField(blank=True, null=True)  # Error details if failed
    
    # Export information
    pdf_report = models.FileField(upload_to='reports/pdf/', blank=True, null=True)
    export_formats = models.JSONField(default=list)  # Formats this report has been exported as
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['target_url']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"Report {self.id}: {self.target_url} ({self.get_status_display()})"
    
    def update_status(self, status, save=True):
        """Update report status with appropriate timestamps"""
        self.status = status
        
        if status == self.Status.IN_PROGRESS and not self.started_at:
            self.started_at = timezone.now()
        elif status == self.Status.COMPLETED and not self.completed_at:
            self.completed_at = timezone.now()
        
        if save:
            self.save()
    
    def update_highest_severity(self):
        """Update highest severity based on findings"""
        severities = {
            'critical': 5,
            'high': 4,
            'medium': 3, 
            'low': 2,
            'info': 1,
            'none': 0
        }
        
        highest = 'none'
        
        # Get counts from findings_summary or calculate them
        if self.findings_summary and 'counts' in self.findings_summary:
            counts = self.findings_summary['counts']
            for sev, count in counts.items():
                if count > 0 and severities.get(sev, 0) > severities.get(highest, 0):
                    highest = sev
        
        self.highest_severity = highest
        return highest


class ReportExport(models.Model):
    """Model for tracking report exports"""
    
    class Format(models.TextChoices):
        PDF = 'pdf', _('PDF')
        CSV = 'csv', _('CSV')
        JSON = 'json', _('JSON')
        HTML = 'html', _('HTML')
    
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='exports')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='report_exports')
    format = models.CharField(max_length=10, choices=Format.choices)
    file = models.FileField(upload_to='reports/exports/')
    created_at = models.DateTimeField(auto_now_add=True)
    options = models.JSONField(default=dict)  # Export options used
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['report', 'format']),
            models.Index(fields=['user', 'created_at']),
        ]
    
    def __str__(self):
        return f"Export of Report {self.report_id} ({self.format})"


class Vulnerability(models.Model):
    """Model for individual vulnerability findings within a report"""
    
    class Severity(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFO = 'info', _('Informational')
    
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.LOW)
    category = models.CharField(max_length=100)
    
    # Additional details
    details = models.JSONField(default=dict)  # Can include path, evidence, recommendation, etc.
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    false_positive = models.BooleanField(default=False)  # Marked as false positive by user
    
    class Meta:
        ordering = ['severity', 'name']
        indexes = [
            models.Index(fields=['report', 'severity']),
            models.Index(fields=['category']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.get_severity_display()}) - Report {self.report_id}"