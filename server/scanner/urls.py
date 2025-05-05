# backend/scanner/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet, ScanResultViewSet


router = DefaultRouter()
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'results', ScanResultViewSet, basename='result')

urlpatterns = [
    path('', include(router.urls)),
    path('scans/<uuid:scan_id>/results/', ScanResultViewSet.as_view({'get': 'list'}), name='scan-results'),
    
]