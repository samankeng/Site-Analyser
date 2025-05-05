from rest_framework import serializers
from .models import Report, ReportExport, Vulnerability

class VulnerabilitySerializer(serializers.ModelSerializer):
    """Serializer for vulnerability findings"""
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    
    class Meta:
        model = Vulnerability
        fields = [
            'id', 'report', 'name', 'description', 'severity', 'severity_display',
            'category', 'details', 'created_at', 'false_positive'
        ]
        read_only_fields = ['id', 'created_at']


class ReportSerializer(serializers.ModelSerializer):
    """Serializer for report list view"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    highest_severity_display = serializers.CharField(source='get_highest_severity_display', read_only=True)
    
    class Meta:
        model = Report
        fields = [
            'id', 'user', 'name', 'target_url', 'status', 'status_display',
            'created_at', 'started_at', 'completed_at', 'scan_types',
            'highest_severity', 'highest_severity_display', 'findings_summary',
            'security_score', 'error_message'  # Added security_score
        ]
        read_only_fields = ['id', 'created_at', 'started_at', 'completed_at']


class ReportDetailSerializer(serializers.ModelSerializer):
    """Serializer for report detail view with full information"""
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    highest_severity_display = serializers.CharField(source='get_highest_severity_display', read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    
    class Meta:
        model = Report
        fields = [
            'id', 'user', 'name', 'target_url', 'status', 'status_display',
            'created_at', 'started_at', 'completed_at', 'scan_types',
            'highest_severity', 'highest_severity_display', 'findings_summary',
            'security_score', 'category_scores','results', 'notes', 'error_message', 'vulnerabilities'  # Added security_score
        ]
        read_only_fields = ['id', 'created_at', 'started_at', 'completed_at']


class ReportExportSerializer(serializers.ModelSerializer):
    """Serializer for report exports"""
    format_display = serializers.CharField(source='get_format_display', read_only=True)
    report_target = serializers.CharField(source='report.target_url', read_only=True)
    
    class Meta:
        model = ReportExport
        fields = [
            'id', 'report', 'report_target', 'user', 'format', 'format_display',
            'file', 'created_at', 'options'
        ]
        read_only_fields = ['id', 'created_at']