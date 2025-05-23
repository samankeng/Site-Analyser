# backend/ai_analyzer/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AIAnalysisViewSet, AIRecommendationViewSet, AnomalyViewSet, AnomalyDetectionModelViewSet


router = DefaultRouter()
router.register(r'analyses', AIAnalysisViewSet, basename='ai-analysis')
router.register(r'recommendations', AIRecommendationViewSet, basename='ai-recommendation')
router.register(r'anomalies', AnomalyViewSet, basename='anomalies')
router.register(r'anomaly-model', AnomalyDetectionModelViewSet, basename='anomaly-model')

urlpatterns = [
    path('', include(router.urls)),

    
]