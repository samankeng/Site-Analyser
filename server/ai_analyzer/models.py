from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from scanner.models import Scan

class AIAnalysis(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='ai_analyses')
    scan_id = models.CharField(max_length=255, unique=True)  # Keep this as a unique identifier
    scan_identifier = models.CharField(max_length=255, null=True, blank=True)  # Rename 'scan' to 'scan_identifier'
    analysis_type = models.CharField(max_length=100)
    analysis_result = models.JSONField()
    confidence_score = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AI Analysis for Scan {self.scan_id}"

class AIRecommendation(models.Model):
    title = models.CharField(max_length=255)
    confidence_score = models.FloatField()
    analysis = models.ForeignKey(AIAnalysis, on_delete=models.CASCADE, related_name='recommendations')
    recommendation_type = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Recommendation for {self.analysis}"

    class Meta:
        ordering = ['-created_at']
        
# Add this to your ai_analyzer/models.py file
class Anomaly(models.Model):
    """Model for storing anomaly detection results"""
    
    class Severity(models.TextChoices):
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='anomalies')
    component = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(
        max_length=10, 
        choices=Severity.choices,
        default=Severity.MEDIUM
    )
    score = models.FloatField()  # Anomaly detection score
    created_at = models.DateTimeField(auto_now_add=True)
    is_false_positive = models.BooleanField(default=False)
    recommendation = models.TextField(blank=True, null=True)
    details = models.JSONField(default=dict)
    
    def __str__(self):
        return f"Anomaly in {self.component} for scan {self.scan_id}"