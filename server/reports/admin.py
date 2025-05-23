from django.contrib import admin
from .models import Report, ReportExport, Vulnerability

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('id', 'target_url', 'user', 'status', 'highest_severity', 'created_at', 'completed_at')
    list_filter = ('status', 'highest_severity', 'created_at')
    search_fields = ('target_url', 'name', 'user__username', 'user__email')
    readonly_fields = ('created_at', 'started_at', 'completed_at')
    date_hierarchy = 'created_at'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'severity', 'category', 'report', 'false_positive')
    list_filter = ('severity', 'category', 'false_positive')
    search_fields = ('name', 'description', 'report__target_url')
    readonly_fields = ('created_at',)


@admin.register(ReportExport)
class ReportExportAdmin(admin.ModelAdmin):
    list_display = ('id', 'report', 'format', 'user', 'created_at')
    list_filter = ('format', 'created_at')
    search_fields = ('report__target_url', 'user__username', 'user__email')
    readonly_fields = ('created_at',)