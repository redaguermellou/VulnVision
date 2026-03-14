from django.db import models
from django.conf import settings
from apps.scans.models import Scan, Vulnerability, OWASPAlert
from apps.targets.models import Target

class ChatSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='chat_sessions')
    target = models.ForeignKey(Target, on_delete=models.SET_NULL, null=True, blank=True)
    scan = models.ForeignKey(Scan, on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=255, default='New Chat')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"{self.title} - {self.user.username}"

class ChatMessage(models.Model):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('assistant', 'Assistant'),
        ('system', 'System'),
    )
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    context_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}"

class RemediationGuide(models.Model):
    vulnerability = models.OneToOneField(Vulnerability, on_delete=models.CASCADE, related_name='ai_remediation', null=True, blank=True)
    owasp_alert = models.OneToOneField(OWASPAlert, on_delete=models.CASCADE, related_name='ai_remediation', null=True, blank=True)
    content = models.JSONField()  # Structured data: steps, snippets, etc.
    html_content = models.TextField() # Cached markdown rendering
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    version = models.IntegerField(default=1)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        title = self.vulnerability.title if self.vulnerability else self.owasp_alert.alert
        return f"Remediation for {title}"
