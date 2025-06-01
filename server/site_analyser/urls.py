# server/site_analyser/urls.py - Updated with compliance routes

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse

# Simple health check view
def health_check(request):
    return JsonResponse({'status': 'ok'})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/health/', health_check, name='health_check'),
    path('api/auth/', include('accounts.urls')),
    path('api/scanner/', include('scanner.urls')),
    path('api/reports/', include('reports.urls')),
    path('api/compliance/', include('compliance.urls')),  # ← ADD THIS LINE
    # path('api/alerts/', include('alerts.urls')),
    path('api/ai-analyzer/', include('ai_analyzer.urls')),
    path('api/', include('api.urls')),
]