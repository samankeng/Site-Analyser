# backend/scanner/admin.py

from django.contrib import admin
from .models import Scan, ScanResult

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'target_url', 'user', 'status', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at')
    search_fields = ('target_url', 'user__email')
    readonly_fields = ('id', 'created_at', 'updated_at', 'started_at', 'completed_at')
    
    fieldsets = (
        (None, {'fields': ('id', 'user', 'target_url')}),
        ('Scan Details', {'fields': ('scan_types', 'status', 'error_message')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at', 'started_at', 'completed_at')}),
    )

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan', 'category', 'name', 'severity', 'created_at')
    list_filter = ('category', 'severity', 'created_at')
    search_fields = ('scan__target_url', 'name', 'description')
    readonly_fields = ('id', 'created_at')
    
    fieldsets = (
        (None, {'fields': ('id', 'scan', 'category')}),
        ('Finding Details', {'fields': ('name', 'description', 'severity', 'details')}),
        ('Timestamps', {'fields': ('created_at',)}),
    )