# backend/ai_analyzer/serializers.py

from rest_framework import serializers
from .models import AIAnalysis, AIRecommendation, Anomaly

class AIRecommendationSerializer(serializers.ModelSerializer):
    """Serializer for AI recommendations"""
    
    class Meta:
        model = AIRecommendation
        fields = ('id', 'title', 'description', 'severity', 
                 'confidence_score', 'created_at', 'recommendation_type')
        read_only_fields = ('id', 'created_at')

class AIAnalysisSerializer(serializers.ModelSerializer):
    """Serializer for AI analysis"""
    recommendations = AIRecommendationSerializer(many=True, read_only=True)
    
    class Meta:
        model = AIAnalysis
        fields = ('id', 'scan_id', 'scan_identifier', 'analysis_type', 
                  'analysis_result', 'confidence_score', 'created_at', 'recommendations')
        read_only_fields = ('id', 'created_at')

# Add this to your ai_analyzer/serializers.py file
class AnomalySerializer(serializers.ModelSerializer):
    """Serializer for anomaly detection results"""
    
    class Meta:
        model = Anomaly
        fields = ('id', 'scan', 'component', 'description', 'severity', 
                  'score', 'created_at', 'is_false_positive', 
                  'recommendation', 'details')
        read_only_fields = ('id', 'created_at')