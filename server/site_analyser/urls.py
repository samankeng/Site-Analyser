# site_analyser/urls.py
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.conf import settings
from django.conf.urls.static import static

def health_check(request):
    from django.http import JsonResponse
    return JsonResponse({'status': 'ok'})

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
    path('api/health/', health_check, name='health_check'),
    path('api/auth/', include('accounts.urls')),
    path('api/scanner/', include('scanner.urls')),
    #path('api/reports/', include('reports.urls')),  # ← This should work now
    path('api/compliance/', include('compliance.urls')),
    path('api/ai-analyzer/', include('ai_analyzer.urls')),
    path('api/', include('api.urls')),
    
    # Serve static files in development
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# IMPORTANT: Put the React app catch-all LAST, and make it more specific
if settings.DEBUG:
    # Only catch non-API routes for the React app
    urlpatterns += [
        re_path(r'^(?!api/).*$', TemplateView.as_view(template_name='index.html'), name='react_app'),
    ]
else:
    # Production static file serving
    urlpatterns += [
        re_path(r'^(?!api/).*$', TemplateView.as_view(template_name='index.html'), name='react_app'),
    ]