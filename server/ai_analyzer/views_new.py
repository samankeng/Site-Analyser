# backend/ai_analyzer/views.py

import logging
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import AIAnalysis, AIRecommendation, Anomaly
from .serializers import AIAnalysisSerializer, AIRecommendationSerializer, AnomalySerializer
from scanner.models import Scan, ScanResult
from celery_app.tasks import run_ai_analysis_task
from .ml.anomaly_detection.model import AnomalyDetectionModel

logger = logging.getLogger(__name__)

class AIAnalysisViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for retrieving AI analysis results"""
    serializer_class = AIAnalysisSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get AI analyses for the current user"""
        return AIAnalysis.objects.filter(user=self.request.user).order_by('-created_at')
    
    @action(detail=False, methods=['post'])
    def analyze(self, request):
        """Trigger AI analysis for a scan"""
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"AI analysis requested for scan {scan_id} by user {request.user.username}")
        
        # Check if scan exists and belongs to the user
        scan = get_object_or_404(Scan, id=scan_id, user=request.user)
        
        # Check if scan is completed
        if scan.status != 'completed':
            return Response(
                {'error': 'Cannot analyze scan that is not completed'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Trigger async analysis task
        run_ai_analysis_task.delay(str(scan.id))
        logger.info(f"AI analysis task queued for scan {scan_id}")
        
        return Response({'message': 'AI analysis started'}, status=status.HTTP_202_ACCEPTED)
    
    @action(detail=False, methods=['get'])
    def for_scan(self, request):
        """Get AI analyses for a specific scan"""
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Fetching AI analyses for scan {scan_id}")
        
        # Get analyses for the specified scan
        analyses = AIAnalysis.objects.filter(
            scan_id=scan_id,
            user=request.user
        ).order_by('-created_at')
        
        logger.info(f"Found {analyses.count()} analyses for scan {scan_id}")
        
        serializer = self.get_serializer(analyses, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def check_analysis_status(self, request):
        """Check the status of AI analysis tasks"""
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Checking analysis status for scan {scan_id}")
        
        # Check if any analyses exist for this scan
        analyses = AIAnalysis.objects.filter(scan_id=scan_id, user=request.user)
        if analyses.exists():
            logger.info(f"Found completed analyses for scan {scan_id}")
            serializer = self.get_serializer(analyses, many=True)
            return Response({
                'status': 'completed',
                'analyses': serializer.data
            })
        
        # Check if task is still running in Celery
        try:
            from celery_app.celery import app
            inspect = app.control.inspect()
            active_tasks = inspect.active() or {}
            
            for worker, tasks in active_tasks.items():
                for task in tasks:
                    if task.get('args') == [scan_id] or task.get('args') == [str(scan_id)]:
                        logger.info(f"Found in-progress analysis task for scan {scan_id} on worker {worker}")
                        return Response({
                            'status': 'in_progress',
                            'worker': worker
                        })
            
            # Also check scheduled and reserved tasks
            scheduled_tasks = inspect.scheduled() or {}
            for worker, tasks in scheduled_tasks.items():
                for task in tasks:
                    if task.get('args') == [scan_id] or task.get('args') == [str(scan_id)]:
                        logger.info(f"Found scheduled analysis task for scan {scan_id} on worker {worker}")
                        return Response({
                            'status': 'scheduled',
                            'worker': worker
                        })
            
            reserved_tasks = inspect.reserved() or {}
            for worker, tasks in reserved_tasks.items():
                for task in tasks:
                    if task.get('args') == [scan_id] or task.get('args') == [str(scan_id)]:
                        logger.info(f"Found reserved analysis task for scan {scan_id} on worker {worker}")
                        return Response({
                            'status': 'reserved',
                            'worker': worker
                        })
        except Exception as e:
            logger.exception(f"Error checking Celery task status: {str(e)}")
            return Response({
                'status': 'error',
                'message': f"Error checking task status: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # No analyses found and no active tasks
        logger.info(f"No analysis or active tasks found for scan {scan_id}")
        return Response({
            'status': 'not_started',
            'message': 'Analysis not found or has not started yet'
        })

    # NEW: Get executive summary
    # Update to the executive_summary method in AIAnalysisViewSet

@action(detail=False, methods=['get'])
def executive_summary(self, request):
    """Get executive summary for a scan with enhanced LLM generation capability"""
    scan_id = request.query_params.get('scan_id')
    if not scan_id:
        return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    logger.info(f"Fetching executive summary for scan {scan_id}")
    
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
    summary = analysis.analysis_result.get('executive_summary')
    
    # If no summary exists but we have LLM analysis, try to generate one
    if not summary and 'llm_analysis' in analysis.analysis_result:
        try:
            logger.info(f"Generating executive summary on-the-fly for analysis {analysis.id}")
            
            # Import the LLM service to generate a summary
            from .services.llm_service import LLMService
            llm_service = LLMService()
            
            # Prepare data for summary generation
            llm_analysis = analysis.analysis_result.get('llm_analysis', {})
            summary_data = {
                'target_url': analysis.scan_identifier,
                'risk_level': llm_analysis.get('risk_level', 'medium'),
                'vulnerabilities': llm_analysis.get('vulnerabilities', []),
                'recommendations': llm_analysis.get('recommendations', [])
            }
            
            # Generate executive summary
            summary = llm_service.generate_executive_summary(summary_data)
            
            # Save it to the analysis for future use
            analysis.analysis_result['executive_summary'] = summary
            analysis.save(update_fields=['analysis_result'])
            
            logger.info(f"Successfully generated and saved executive summary for analysis {analysis.id}")
        except ImportError:
            logger.error("LLMService not available for summary generation")
            return Response(
                {'error': 'Executive summary generation service not available'},
                status=status.HTTP_501_NOT_IMPLEMENTED
            )
        except Exception as e:
            logger.exception(f"Error generating executive summary: {str(e)}")
            return Response(
                {'error': f'Failed to generate executive summary: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # If we still don't have a summary, return an error
    if not summary:
        return Response(
            {'error': 'No executive summary available and unable to generate one'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    return Response({
        'summary': summary,
        'analysis_id': str(analysis.id)
    })
    
    # NEW: Get LLM analysis
    @action(detail=False, methods=['get'])
    def llm_analysis(self, request):
        """Get LLM analysis for a specific analysis"""
        analysis_id = request.query_params.get('analysis_id')
        if not analysis_id:
            return Response({'error': 'analysis_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Fetching LLM analysis for analysis {analysis_id}")
        
        # Get the analysis
        analysis = get_object_or_404(AIAnalysis, id=analysis_id, user=request.user)
        
        # Check if analysis has LLM analysis
        llm_analysis = analysis.analysis_result.get('llm_analysis')
        if not llm_analysis:
            return Response(
                {'error': 'No LLM analysis available for this analysis'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        return Response(llm_analysis)

class AIRecommendationViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for retrieving AI recommendations"""
    serializer_class = AIRecommendationSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get AI recommendations for the current user"""
        return AIRecommendation.objects.filter(
            analysis__user=self.request.user
        ).order_by('-severity', '-created_at')
    
    @action(detail=False, methods=['get'])
    def for_analysis(self, request):
        """Get recommendations for a specific analysis"""
        analysis_id = request.query_params.get('analysis_id')
        if not analysis_id:
            return Response({'error': 'analysis_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Fetching recommendations for analysis {analysis_id}")
        
        # Get recommendations for the specified analysis
        recommendations = AIRecommendation.objects.filter(
            analysis_id=analysis_id,
            analysis__user=self.request.user
        ).order_by('-severity', '-created_at')
        
        logger.info(f"Found {recommendations.count()} recommendations for analysis {analysis_id}")
        
        serializer = self.get_serializer(recommendations, many=True)
        return Response(serializer.data)
    
    # NEW: Get LLM recommendations
    @action(detail=False, methods=['get'])
    def llm_recommendations(self, request):
        """Get LLM-generated recommendations for a specific analysis"""
        analysis_id = request.query_params.get('analysis_id')
        if not analysis_id:
            return Response({'error': 'analysis_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Fetching LLM recommendations for analysis {analysis_id}")
        
        # Get LLM recommendations for the specified analysis
        recommendations = AIRecommendation.objects.filter(
            analysis_id=analysis_id,
            analysis__user=self.request.user,
            recommendation_type='llm'  # Filter by LLM recommendation type
        ).order_by('-severity', '-created_at')
        
        logger.info(f"Found {recommendations.count()} LLM recommendations for analysis {analysis_id}")
        
        serializer = self.get_serializer(recommendations, many=True)
        return Response(serializer.data)

# Add this new ViewSet to handle anomaly requests
class AnomalyViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for retrieving anomaly detection results"""
    serializer_class = AnomalySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Get anomalies for the current user"""
        return Anomaly.objects.filter(
            scan__user=self.request.user
        ).order_by('-severity', '-created_at')
    
    @action(detail=False, methods=['get'])
    def for_scan(self, request):
        """Get anomalies for a specific scan"""
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        # Get anomalies for the specified scan
        anomalies = self.get_queryset().filter(scan_id=scan_id)
        serializer = self.get_serializer(anomalies, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get statistics about anomalies"""
        anomalies = self.get_queryset()
        
        stats = {
            'total': anomalies.count(),
            'by_severity': {
                'high': anomalies.filter(severity='high').count(),
                'medium': anomalies.filter(severity='medium').count(),
                'low': anomalies.filter(severity='low').count(),
            },
            'by_component': {},
        }
        
        # Count by component
        for anomaly in anomalies:
            component = anomaly.component
            stats['by_component'][component] = stats['by_component'].get(component, 0) + 1
        
        return Response(stats)
    
    @action(detail=True, methods=['post'])
    def false_positive(self, request, pk=None):
        """Mark an anomaly as a false positive"""
        anomaly = self.get_object()
        anomaly.is_false_positive = True
        anomaly.save()
        
        serializer = self.get_serializer(anomaly)
        return Response(serializer.data)

class AnomalyDetectionModelViewSet(viewsets.ViewSet):
    """ViewSet for managing anomaly detection model"""
    permission_classes = [permissions.IsAdminUser]
    
    @action(detail=False, methods=['post'])
    def train(self, request):
        """Train the anomaly detection model with historical data"""
        try:
            # Get training data from recent scans
            scan_results = ScanResult.objects.all().order_by('-created_at')[:1000]
            training_data = self._prepare_training_data(scan_results)
            
            # Initialize and train model
            model = AnomalyDetectionModel()
            success = model.train_model(training_data)
            
            if success:
                return Response({'message': 'Model trained successfully'})
            else:
                return Response({'error': 'Model training failed'}, 
                              status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.exception("Error training model")
            return Response({'error': str(e)}, 
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['get'])
    def status(self, request):
        """Get model status and metrics"""
        model = AnomalyDetectionModel()
        return Response({
            'model_loaded': model.model is not None,
            'feature_names': model.feature_names,
            'threshold': model.threshold,
            'model_path': model.model_path
        })
    
    def _prepare_training_data(self, scan_results):
        """Prepare scan results for model training"""
        features = []
        labels = []
        
        for result in scan_results:
            feature_vector = self._extract_features_for_training(result)
            label = 1 if result.severity in ['critical', 'high'] else 0
            
            features.append(feature_vector)
            labels.append(label)
        
        return {'features': features, 'labels': labels}
    
    def _extract_features_for_training(self, scan_result):
        """Extract features from scan result for training"""
        features = []
        details = scan_result.details
        
        # Basic features
        features.append(details.get('response_time', 0))
        features.append(len(details.get('headers', {})))
        features.append(details.get('ssl_score', 0))
        features.append(details.get('content_size', 0))
        features.append(len(details.get('external_resources', [])))
        
        # Add more features as needed
        return features