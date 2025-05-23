# New file: backend/ai_analyzer/executive_summary_view.py

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import logging
from django.shortcuts import get_object_or_404
from .models import AIAnalysis

logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_executive_summary(request):
    """Standalone view function for retrieving executive summary"""
    scan_id = request.GET.get('scan_id')
    if not scan_id:
        return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    logger.info(f"Direct endpoint: Fetching executive summary for scan {scan_id}")
    
    # Get the most recent analysis for this scan
    analysis = AIAnalysis.objects.filter(
        scan_id=scan_id,
        user=request.user
    ).order_by('-created_at').first()
    
    if not analysis:
        return Response(
            {'error': 'No analysis found for this scan'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if analysis has executive summary
    summary = analysis.analysis_result.get('executive_summary', '')
    
    # Return a simple response even if no summary exists
    if not summary:
        summary = "No executive summary is available for this analysis."
    
    return Response({
        'summary': summary,
        'analysis_id': str(analysis.id)
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_executive_summary_by_id(request, id):
    """Standalone view function for retrieving executive summary by scan ID in the URL path"""
    scan_id = id
    
    logger.info(f"Direct endpoint: Fetching executive summary for scan {scan_id} via path parameter")
    
    # Get the most recent analysis for this scan
    analysis = AIAnalysis.objects.filter(
        scan_id=scan_id,
        user=request.user
    ).order_by('-created_at').first()
    
    if not analysis:
        return Response(
            {'error': 'No analysis found for this scan'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if analysis has executive summary
    summary = analysis.analysis_result.get('executive_summary', '')
    
    # Return a simple response even if no summary exists
    if not summary:
        summary = "No executive summary is available for this analysis."
    
    return Response({
        'summary': summary,
        'analysis_id': str(analysis.id)
    })