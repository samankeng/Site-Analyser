# backend/celery_app/tasks.py

from celery import shared_task
from django.utils import timezone
import logging
import uuid

logger = logging.getLogger(__name__)

@shared_task
def start_scan_task(scan_id):
    """Celery task to run a scan asynchronously"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from scanner.services.scan_service import ScanService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Update scan status to in progress
        scan.status = 'in_progress'
        scan.started_at = timezone.now()
        scan.save()
        
        # Initialize and run the scan
        scanner = ScanService(scan)
        scanner.run()
        
        # Update scan status to completed
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save()
        
        return {"status": "success", "scan_id": scan_id, }
    
    except Exception as e:
        logger.exception(f"Error running scan {scan_id}: {str(e)}")
        
        # Update scan status to failed
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
        except Exception as update_error:
            logger.exception(f"Error updating scan status: {str(update_error)}")
        
        return {"status": "error", "message": str(e)}

@shared_task
def run_ai_analysis_task(scan_id):
    """Celery task to run AI analysis on scan results"""
    try:
        # Lazy import to avoid circular imports
        from scanner.models import Scan
        from server.ai_analyzer.services.ai_analysis_new import AIAnalysisService
        
        # Get the scan object
        scan = Scan.objects.get(id=scan_id)
        
        # Check if scan is completed
        if scan.status != 'completed':
            raise ValueError(f"Cannot analyze scan that is not completed. Current status: {scan.status}")
        
        # Run the AI analysis
        analysis_service = AIAnalysisService(scan)
        analysis_service.analyze()
        
        return {"status": "success", "scan_id": scan_id}
    
    except Exception as e:
        logger.exception(f"Error running AI analysis for scan {scan_id}: {str(e)}")
        return {"status": "error", "message": str(e)}
