# backend/ai_analyzer/admin.py

from django.contrib import admin
from .models import AIAnalysis, AIRecommendation

@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    list_display = ('scan_id', 'user', 'analysis_type', 'confidence_score', 'created_at')
    list_filter = ('analysis_type', 'created_at')
    search_fields = ('scan_id', 'user__username')

@admin.register(AIRecommendation)
class AIRecommendationAdmin(admin.ModelAdmin):
    list_display = ('analysis', 'recommendation_type', 'severity', 'created_at')
    list_filter = ('recommendation_type', 'severity', 'created_at')
    search_fields = ('description',)