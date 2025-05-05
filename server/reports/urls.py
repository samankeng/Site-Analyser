from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register our viewsets
router = DefaultRouter()
router.register(r'reports', views.ReportViewSet, basename='report')
router.register(r'vulnerabilities', views.VulnerabilityViewSet, basename='vulnerability')
router.register(r'exports', views.ReportExportViewSet, basename='export')

# Wire up our API using automatic URL routing
urlpatterns = [
    path('', include(router.urls)),
]