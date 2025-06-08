# backend/api/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from django.contrib import admin

# Schema view for Swagger documentation
schema_view = get_schema_view(
   openapi.Info(
      title="Site Analyser API",
      default_version='v1',
      description="Security scanning API for web applications",
      contact=openapi.Contact(email="contact@site-analyser.com"),
      license=openapi.License(name="MIT License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)



urlpatterns = [
    # Authentication endpoints
    path('auth/', include('accounts.urls')),
    
    # Scanner endpoints
    path('scanner/', include('scanner.urls')),
    
    # AI Analyzer endpoints
    path('ai-analyzer/', include('ai_analyzer.urls')),
    
    # API documentation
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
]