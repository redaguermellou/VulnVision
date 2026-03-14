from django.contrib import admin
from .models import Scan, Vulnerability

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'target', 'scan_type', 'status', 'created_at', 'critical_count', 'high_count')
    list_filter = ('scan_type', 'status', 'created_at')
    search_fields = ('name', 'target__name', 'target__url')
    readonly_fields = ('created_at', 'updated_at', 'started_at', 'completed_at')
    
    fieldsets = (
        ('Overview', {
            'fields': ('user', 'target', 'name', 'scan_type', 'status')
        }),
        ('Schedule', {
            'fields': ('created_at', 'started_at', 'completed_at')
        }),
        ('Results Counters', {
            'fields': ('critical_count', 'high_count', 'medium_count', 'low_count', 'info_count')
        }),
        ('Configuration', {
            'fields': ('config',),
            'classes': ('collapse',)
        }),
    )

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('title', 'target', 'severity', 'component', 'cve_id', 'created_at')
    list_filter = ('severity', 'created_at')
    search_fields = ('title', 'description', 'target__name', 'cve_id')
    readonly_fields = ('created_at', 'updated_at')
