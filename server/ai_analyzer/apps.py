# Add this to your backend/ai_analyzer/apps.py file
# This will print all the available routes when the Django app starts

from django.apps import AppConfig

class AiAnalyzerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ai_analyzer'

    def ready(self):
        # This will run when the app is ready
        from django.urls import get_resolver
        from django.conf import settings
        
        # Only print in debug mode
        if settings.DEBUG:
            print("\n=== AI Analyzer API Routes ===")
            all_urls = get_resolver().url_patterns
            for pattern in all_urls:
                if hasattr(pattern, 'url_patterns'):
                    for url in pattern.url_patterns:
                        if 'ai-analyzer' in str(url.pattern):
                            print(f"Route: {url.pattern}")
            print("===========================\n")