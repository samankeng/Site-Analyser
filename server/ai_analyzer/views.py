# backend/ai_analyzer/views.py

import logging
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import AIAnalysis, AIRecommendation, Anomaly
from .serializers import AIAnalysisSerializer, AIRecommendationSerializer, AnomalySerializer
from scanner.models import Scan , ScanResult
from celery_app.tasks import run_ai_analysis_task
from .ml.anomaly_detection.model import AnomalyDetectionModel  # Add this import
from rest_framework.decorators import api_view


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
            analysis__user=request.user
        ).order_by('-severity', '-created_at')
        
        logger.info(f"Found {recommendations.count()} recommendations for analysis {analysis_id}")
        
        serializer = self.get_serializer(recommendations, many=True)
        return Response(serializer.data)

# Add to ai_analyzer/views.py
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
    
    @action(detail=False, methods=['get'])
    def for_scan_enhanced(self, request):
        """Enhanced anomaly retrieval that checks multiple sources"""
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        # This will use the new get_anomalies_for_scan function
        return get_anomalies_for_scan(request)

@api_view(['GET'])
def get_anomalies_for_scan(request):
    """Get anomalies for a specific scan - handles both AI analysis anomalies and Anomaly model anomalies"""
    try:
        scan_id = request.query_params.get('scan_id')
        
        if not scan_id:
            return Response({
                'success': False,
                'error': 'scan_id parameter is required'
            }, status=400)
        
        logger.info(f"Fetching anomalies for scan {scan_id}")
        
        # Get the scan
        scan = get_object_or_404(Scan, id=scan_id, user=request.user)
        
        all_anomalies = []
        
        # METHOD 1: Check for anomalies in AI Analysis results
        try:
            analysis = AIAnalysis.objects.get(scan=scan)
            logger.info(f"Found AI analysis for scan {scan_id}")
            
            # Get anomaly data from analysis results
            analysis_result = analysis.analysis_result or {}
            anomaly_data = analysis_result.get('anomaly_detection', {})
            
            if anomaly_data.get('is_anomaly', False):
                anomalies = anomaly_data.get('anomalies', [])
                logger.info(f"Found {len(anomalies)} anomalies in AI analysis")
                
                # Transform backend anomaly format to frontend format
                for i, anomaly in enumerate(anomalies):
                    transformed_anomaly = {
                        'id': f"ai-anomaly-{scan_id}-{i}",
                        'component': get_component_name_from_type(anomaly.get('type', 'unknown')),
                        'severity': anomaly.get('severity', 'medium'),
                        'description': anomaly.get('description', 'No description available'),
                        'recommendation': anomaly.get('recommendation', None),
                        'score': anomaly_data.get('anomaly_score', 0.5),
                        'details': anomaly.get('details', {}),
                        'created_at': analysis.created_at.isoformat(),
                        'is_false_positive': False,
                        'type': anomaly.get('type', 'unknown'),
                        'affected_items': anomaly.get('affected_items', 0),
                        'source': 'ai_analysis'
                    }
                    all_anomalies.append(transformed_anomaly)
                    
        except AIAnalysis.DoesNotExist:
            logger.info(f"No AI analysis found for scan {scan_id}")
        
        # METHOD 2: Check for anomaly recommendations
        try:
            recommendations = AIRecommendation.objects.filter(
                analysis__scan=scan,
                title__startswith='Enhanced Anomaly:'
            )
            
            if recommendations.exists():
                logger.info(f"Found {recommendations.count()} anomaly recommendations")
                
                for rec in recommendations:
                    anomaly = {
                        'id': f"rec-{rec.id}",
                        'component': rec.title.replace('Enhanced Anomaly: ', ''),
                        'severity': rec.severity,
                        'description': rec.description,
                        'recommendation': rec.recommendation,
                        'score': rec.confidence_score,
                        'details': {},
                        'created_at': rec.created_at.isoformat(),
                        'is_false_positive': False,
                        'type': 'recommendation_based',
                        'source': 'ai_recommendations'
                    }
                    all_anomalies.append(anomaly)
                    
        except Exception as e:
            logger.warning(f"Error fetching anomaly recommendations: {str(e)}")
        
        # METHOD 3: Check your existing Anomaly model
        try:
            anomaly_objects = Anomaly.objects.filter(scan=scan)
            
            if anomaly_objects.exists():
                logger.info(f"Found {anomaly_objects.count()} anomaly objects")
                
                for anomaly_obj in anomaly_objects:
                    anomaly = {
                        'id': f"model-{anomaly_obj.id}",
                        'component': anomaly_obj.component,
                        'severity': anomaly_obj.severity,
                        'description': anomaly_obj.description,
                        'recommendation': getattr(anomaly_obj, 'recommendation', None),
                        'score': getattr(anomaly_obj, 'score', 0.5),
                        'details': getattr(anomaly_obj, 'details', {}),
                        'created_at': anomaly_obj.created_at.isoformat(),
                        'is_false_positive': getattr(anomaly_obj, 'is_false_positive', False),
                        'type': getattr(anomaly_obj, 'anomaly_type', 'model_based'),
                        'source': 'anomaly_model'
                    }
                    all_anomalies.append(anomaly)
                    
        except Exception as e:
            logger.warning(f"Error fetching anomaly model objects: {str(e)}")
        
        # Remove duplicates and sort by severity
        unique_anomalies = []
        seen_descriptions = set()
        
        for anomaly in all_anomalies:
            description_key = f"{anomaly['component']}-{anomaly['description'][:50]}"
            if description_key not in seen_descriptions:
                unique_anomalies.append(anomaly)
                seen_descriptions.add(description_key)
        
        # Sort by severity (critical > high > medium > low)
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        unique_anomalies.sort(
            key=lambda x: severity_order.get(x['severity'], 0), 
            reverse=True
        )
        
        logger.info(f"Returning {len(unique_anomalies)} unique anomalies for scan {scan_id}")
        
        if unique_anomalies:
            # Calculate overall anomaly score
            avg_score = sum(a.get('score', 0) for a in unique_anomalies) / len(unique_anomalies)
            
            return Response({
                'success': True,
                'data': {
                    'anomalies': unique_anomalies,
                    'anomaly_score': avg_score,
                    'is_anomaly': True,
                    'detection_method': 'enhanced_multi_source',
                    'total_count': len(unique_anomalies)
                }
            })
        else:
            return Response({
                'success': True,
                'data': {
                    'anomalies': [],
                    'anomaly_score': 0.0,
                    'is_anomaly': False,
                    'detection_method': 'none',
                    'total_count': 0
                }
            })
                
    except Exception as e:
        logger.exception(f"Error getting anomalies for scan {scan_id}: {str(e)}")
        return Response({
            'success': False,
            'error': str(e)
        }, status=500)

def get_component_name_from_type(anomaly_type):
    """Convert anomaly type to user-friendly component name"""
    type_to_component_map = {
        'missing_security_headers': 'Security Headers',
        'critical_security_headers_missing': 'Critical Security Headers',
        'ssl_configuration_issues': 'SSL/TLS Configuration',
        'medium_severity_concentration': 'Issue Concentration Analysis',
        'high_severity_concentration': 'High Severity Issues',
        'excessive_issue_count': 'Issue Volume Analysis',
        'vulnerability_cluster': 'Vulnerability Clustering',
        'critical_vulnerability_cluster': 'Critical Vulnerabilities',
        'performance_degradation': 'Performance Analysis',
        'connection_timeouts': 'Connection Issues',
        'ssl_test_site_patterns': 'SSL Test Site Detection',
        'content_security_issues': 'Content Security',
        'scan_failure_anomalies': 'Scan Quality',
        'unknown': 'General Analysis'
    }
    
    return type_to_component_map.get(anomaly_type, 'General Analysis')