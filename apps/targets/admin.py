from django.contrib import admin
from .models import Target

@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'user', 'is_active', 'created_at')
    list_filter = ('is_active', 'protocol', 'created_at')
    search_fields = ('name', 'url', 'ip_address', 'description', 'tags')
    readonly_fields = ('created_at', 'updated_at')
    
    def save_model(self, request, obj, form, change):
        if not obj.pk:
            obj.user = request.user
        super().save_model(request, obj, form, change)
