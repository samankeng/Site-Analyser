# backend/scanner/serializers.py

from rest_framework import serializers
from .models import Scan, ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    """Serializer for scan result objects"""
    
    class Meta:
        model = ScanResult
        fields = ('id', 'category', 'name', 'description', 'severity', 'details', 'created_at')
        read_only_fields = ('id', 'created_at')

class ScanSerializer(serializers.ModelSerializer):
    """Serializer for scan objects"""
    results = ScanResultSerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = ('id', 'target_url', 'scan_types', 'status', 'created_at', 
                 'updated_at', 'started_at', 'completed_at', 'error_message', 'results')
        read_only_fields = ('id', 'status', 'created_at', 'updated_at', 
                           'started_at', 'completed_at', 'error_message')

class ScanCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating scan objects"""
    
    class Meta:
        model = Scan
        fields = ('target_url', 'scan_types')
    
    def create(self, validated_data):
        # Add the current user to the scan
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)