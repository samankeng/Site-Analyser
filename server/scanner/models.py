# backend/scanner/models.py

from django.db import models
from django.conf import settings
import uuid

class Scan(models.Model):
    """Model for security scan requests"""
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target_url = models.URLField(max_length=255)
    scan_types = models.JSONField(default=list)  # List of scan types to perform
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    def __str__(self):
        return f"Scan {self.id} - {self.target_url} ({self.status})"

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