from django.shortcuts import get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.conf import settings

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

import os
import json
import csv
import tempfile
from datetime import datetime
import io

# Removed WeasyPrint and reportlab imports

from .models import Report, ReportExport, Vulnerability
from .serializers import (
    ReportSerializer, 
    ReportDetailSerializer,
    VulnerabilitySerializer,
    ReportExportSerializer
)

class ReportViewSet(viewsets.ModelViewSet):
    """ViewSet for viewing and editing security reports"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReportSerializer
    
    def get_queryset(self):
        """Filter reports to return only those belonging to the current user"""
        return Report.objects.filter(user=self.request.user)
    
    def get_serializer_class(self):
        """Return different serializers for list and detail views"""
        if self.action == 'retrieve':
            return ReportDetailSerializer
        return self.serializer_class
    
    @action(detail=True, methods=['get'])
    def vulnerabilities(self, request, pk=None):
        """Get all vulnerabilities for a specific report"""
        report = self.get_object()
        vulnerabilities = Vulnerability.objects.filter(report=report)
        serializer = VulnerabilitySerializer(vulnerabilities, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def pdf(self, request, pk=None):
        """Generate and return a PDF version of the report"""
        report = self.get_object()
        
        # Simplified response - return a placeholder message
        return HttpResponse(
            "PDF generation is currently disabled. This feature will be available soon.",
            content_type="text/plain"
        )
    
    @action(detail=False, methods=['post'])
    def export(self, request):
        """Export multiple reports in specified format"""
        # Get report IDs and format from request
        report_ids = request.data.get('report_ids', [])
        export_format = request.data.get('format', 'pdf')
        options = request.data.get('options', {})
        
        if not report_ids:
            return Response(
                {'detail': 'No reports specified for export'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify all reports belong to the user
        reports = Report.objects.filter(id__in=report_ids, user=request.user)
        
        if len(reports) != len(report_ids):
            return Response(
                {'detail': 'One or more reports not found or not accessible'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Handle export based on format
        if export_format == 'pdf':
            return self._export_pdf(reports, options)
        elif export_format == 'csv':
            return self._export_csv(reports, options)
        elif export_format == 'json':
            return self._export_json(reports, options)
        elif export_format == 'html':
            return self._export_html(reports, options)
        else:
            return Response(
                {'detail': f'Unsupported export format: {export_format}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _export_pdf(self, reports, options):
        """Export reports as PDF - simplified version"""
        return HttpResponse(
            "PDF export is currently disabled. This feature will be available soon.",
            content_type="text/plain"
        )
    
    def _export_csv(self, reports, options):
        """Export reports as CSV"""
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="security-reports-{datetime.now().strftime("%Y%m%d")}.csv"'
        
        writer = csv.writer(response)
        # Write header row
        writer.writerow([
            'Report ID', 
            'Target URL', 
            'Status',
            'Created Date',
            'Completed Date',
            'Highest Severity', 
            'Critical',
            'High',
            'Medium',
            'Low',
            'Info'
        ])
        
        # Write data rows
        for report in reports:
            counts = report.findings_summary.get('counts', {}) if report.findings_summary else {}
            writer.writerow([
                report.id,
                report.target_url,
                report.get_status_display(),
                report.created_at.strftime('%Y-%m-%d'),
                report.completed_at.strftime('%Y-%m-%d') if report.completed_at else 'N/A',
                report.get_highest_severity_display(),
                counts.get('critical', 0),
                counts.get('high', 0),
                counts.get('medium', 0),
                counts.get('low', 0),
                counts.get('info', 0)
            ])
        
        return response
    
    def _export_json(self, reports, options):
        """Export reports as JSON"""
        # Serialize reports to JSON
        serializer = ReportDetailSerializer(reports, many=True)
        
        response = HttpResponse(content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="security-reports-{datetime.now().strftime("%Y%m%d")}.json"'
        
        json.dump(serializer.data, response, indent=2)
        return response
    
    def _export_html(self, reports, options):
        """Export reports as HTML"""
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Reports - {datetime.now().strftime('%Y-%m-%d')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                .report {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; }}
                .critical {{ color: #d9534f; }}
                .high {{ color: #f0ad4e; }}
                .medium {{ color: #5bc0de; }}
                .low {{ color: #777; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Security Reports Export</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            <p>Number of reports: {reports.count()}</p>
        """
        
        for report in reports:
            html_content += f"""
            <div class="report">
                <h2>Report: {report.target_url}</h2>
                <p><strong>Status:</strong> {report.get_status_display()}</p>
                <p><strong>Created:</strong> {report.created_at.strftime('%Y-%m-%d')}</p>
                <p><strong>Completed:</strong> {report.completed_at.strftime('%Y-%m-%d') if report.completed_at else 'N/A'}</p>
                <p><strong>Highest Severity:</strong> <span class="{report.highest_severity}">{report.get_highest_severity_display()}</span></p>
            """
            
            # Add vulnerability summary if available
            if report.findings_summary and 'counts' in report.findings_summary:
                counts = report.findings_summary['counts']
                html_content += f"""
                <h3>Findings Summary:</h3>
                <table>
                    <tr>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Info</th>
                    </tr>
                    <tr>
                        <td class="critical">{counts.get('critical', 0)}</td>
                        <td class="high">{counts.get('high', 0)}</td>
                        <td class="medium">{counts.get('medium', 0)}</td>
                        <td class="low">{counts.get('low', 0)}</td>
                        <td>{counts.get('info', 0)}</td>
                    </tr>
                </table>
                """
            
            # Include detailed findings if requested
            if options.get('details', False):
                vulnerabilities = Vulnerability.objects.filter(report=report)
                if vulnerabilities:
                    html_content += """
                    <h3>Detailed Findings:</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Description</th>
                        </tr>
                    """
                    
                    for vuln in vulnerabilities:
                        html_content += f"""
                        <tr>
                            <td>{vuln.name}</td>
                            <td class="{vuln.severity}">{vuln.get_severity_display()}</td>
                            <td>{vuln.category}</td>
                            <td>{vuln.description}</td>
                        </tr>
                        """
                    
                    html_content += "</table>"
            
            html_content += "</div>"
        
        html_content += """
        </body>
        </html>
        """
        
        response = HttpResponse(html_content, content_type='text/html')
        response['Content-Disposition'] = f'attachment; filename="security-reports-{datetime.now().strftime("%Y%m%d")}.html"'
        
        return response
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get report statistics for the current user"""
        user_reports = Report.objects.filter(user=request.user)
        
        # Count reports by status
        status_counts = {
            'total': user_reports.count(),
            'completed': user_reports.filter(status=Report.Status.COMPLETED).count(),
            'in_progress': user_reports.filter(status=Report.Status.IN_PROGRESS).count(),
            'pending': user_reports.filter(status=Report.Status.PENDING).count(),
            'failed': user_reports.filter(status=Report.Status.FAILED).count(),
        }
        
        # Count vulnerabilities by severity
        vulnerability_counts = {
            'critical': Vulnerability.objects.filter(report__in=user_reports, severity=Vulnerability.Severity.CRITICAL).count(),
            'high': Vulnerability.objects.filter(report__in=user_reports, severity=Vulnerability.Severity.HIGH).count(),
            'medium': Vulnerability.objects.filter(report__in=user_reports, severity=Vulnerability.Severity.MEDIUM).count(),
            'low': Vulnerability.objects.filter(report__in=user_reports, severity=Vulnerability.Severity.LOW).count(),
            'info': Vulnerability.objects.filter(report__in=user_reports, severity=Vulnerability.Severity.INFO).count(),
        }
        
        return Response({
            'status_counts': status_counts,
            'vulnerability_counts': vulnerability_counts,
        })


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """ViewSet for viewing and editing vulnerabilities"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VulnerabilitySerializer
    
    def get_queryset(self):
        """Filter vulnerabilities to only those in reports owned by the user"""
        return Vulnerability.objects.filter(report__user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def toggle_false_positive(self, request, pk=None):
        """Toggle the false positive flag for a vulnerability"""
        vulnerability = self.get_object()
        vulnerability.false_positive = not vulnerability.false_positive
        vulnerability.save()
        
        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)


class ReportExportViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing report exports"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ReportExportSerializer
    
    def get_queryset(self):
        """Filter exports to return only those belonging to the current user"""
        return ReportExport.objects.filter(user=self.request.user)