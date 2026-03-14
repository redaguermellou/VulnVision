from django.db import models
from django.conf import settings
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class Target(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='targets')
    name = models.CharField(max_length=255)
    url = models.URLField(validators=[URLValidator()])
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    description = models.TextField(blank=True)
    protocol = models.CharField(max_length=10, choices=[('http', 'HTTP'), ('https', 'HTTPS')], default='https')
    is_active = models.BooleanField(default=True)
    tags = models.CharField(max_length=255, blank=True, help_text="Comma-separated tags")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.url})"

    def clean(self):
        # Additional custom validation if needed
        super().clean()

    def get_scan_count(self):
        # Placeholder for future Scan model relationship
        return 0

    def get_vulnerability_count(self):
        # Placeholder for future Vulnerability model relationship
        return 0

    def get_last_scan(self):
        # Placeholder for future Scan model relationship
        return None
