# server/api/views.py - Add a simple health check endpoint

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """Simple health check endpoint for Docker"""
    return JsonResponse({
        'status': 'healthy',
        'message': 'API is running'
    })

# Or create a separate file: server/api/health.py
from django.http import JsonResponse

def health_check(request):
    """Health check endpoint"""
    return JsonResponse({'status': 'ok'})