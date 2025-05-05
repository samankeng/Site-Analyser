# backend/scanner/views.py

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import HttpResponse
from .models import Scan, ScanResult
from .serializers import ScanSerializer, ScanCreateSerializer, ScanResultSerializer
from celery_app.tasks import start_scan_task
from .services.pdf_report_generator import PDFReportGenerator

import logging

logger = logging.getLogger(__name__)

class ScanViewSet(viewsets.ModelViewSet):
    """Viewset for scan operations with enhanced PDF report generation"""
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        # Only return scans belonging to the authenticated user
        return Scan.objects.filter(user=self.request.user).order_by('-created_at')
    
    def get_serializer_class(self):
        if self.action == 'create':
            return ScanCreateSerializer
        return self.serializer_class
    
    def perform_create(self, serializer):
        scan = serializer.save()
        # Trigger the scan task asynchronously
        start_scan_task.delay(str(scan.id))
        return scan
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status in ['pending', 'in_progress']:
            scan.status = 'failed'
            scan.error_message = 'Scan cancelled by user'
            scan.save()
            return Response({'message': 'Scan cancelled'}, status=status.HTTP_200_OK)
        return Response({'error': 'Cannot cancel scan with status: ' + scan.status}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def pdf(self, request, pk=None):
        """Generate a comprehensive PDF report for a scan with detailed findings and visualizations"""
        scan = self.get_object()
        
        try:
            # Get scan results
            results = ScanResult.objects.filter(scan=scan).order_by('severity')
            
            # Generate the PDF report
            report_generator = PDFReportGenerator(scan, results)
            pdf_data = report_generator.generate_pdf()
            
            # Create the HTTP response with PDF content
            response = HttpResponse(content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="security-scan-{scan.id}.pdf"'
            response.write(pdf_data)
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating PDF for scan {scan.id}: {str(e)}")
            return Response(
                {'error': f'Failed to generate PDF report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


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