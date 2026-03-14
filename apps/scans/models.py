from django.db import models
from django.conf import settings
from django.utils import timezone
from apps.targets.models import Target

class Scan(models.Model):
    SCAN_TYPES = (
        ('nmap', 'Network Scan (Nmap)'),
        ('nikto', 'Web Vulnerability Scan (Nikto)'),
        ('gobuster', 'Directory Bruteforce (Gobuster)'),
        ('zap', 'Web Scan (OWASP ZAP)'),
        ('nuclei', 'Vulnerability Scan (Nuclei)'),
        ('custom', 'Custom Script'),
    )

    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('stopped', 'Stopped'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='scans')
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES, default='nmap')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    config = models.JSONField(default=dict, blank=True)
    progress = models.IntegerField(default=0)  # 0 to 100
    current_phase = models.CharField(max_length=255, blank=True, default='Pending...')
    
    # Statistics/Counts
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.target.name} ({self.status})"

    def is_running(self):
        return self.status == 'running'

    def get_duration(self):
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        elif self.started_at:
            return timezone.now() - self.started_at
        return None

    def update_counts(self):
        """Update finding counts from associated vulnerabilities"""
        vulns = self.vulnerabilities.all()
        self.critical_count = vulns.filter(severity='critical').count()
        self.high_count = vulns.filter(severity='high').count()
        self.medium_count = vulns.filter(severity='medium').count()
        self.low_count = vulns.filter(severity='low').count()
        self.info_count = vulns.filter(severity='info').count()
        self.save()

class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    )

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='info')
    
    STATUS_CHOICES = (
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    
    # Finding details
    component = models.CharField(max_length=255, blank=True, help_text="Port/Path/Service affected")
    evidence = models.TextField(blank=True, help_text="Payload or proof of concept")
    remediation = models.TextField(blank=True)
    cve_id = models.CharField(max_length=50, blank=True, verbose_name="CVE ID")
    cwe_id = models.CharField(max_length=50, blank=True, verbose_name="CWE ID")
    cwe_category = models.CharField(max_length=255, blank=True, null=True)
    
    owasp_category = models.CharField(max_length=100, blank=True, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-severity', '-created_at']
        verbose_name_plural = "Vulnerabilities"

    def __str__(self):
        return f"{self.title} ({self.severity})"

class OWASPScan(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    scan_id = models.CharField(max_length=100, blank=True) # ZAP Scan ID
    status = models.CharField(max_length=50, default='pending')
    progress = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"OWASP Scan - {self.target.name} ({self.status})"

class OWASPAlert(models.Model):
    owasp_scan = models.ForeignKey(OWASPScan, on_delete=models.CASCADE, related_name='alerts')
    alert = models.CharField(max_length=255)
    risk = models.CharField(max_length=50) # Critical, High, Medium, Low, Informational
    reliability = models.CharField(max_length=50)
    url = models.URLField(max_length=1000)
    description = models.TextField()
    solution = models.TextField()
    param = models.CharField(max_length=255, blank=True)
    evidence = models.TextField(blank=True)
    cweid = models.CharField(max_length=50, blank=True)
    wascid = models.CharField(max_length=50, blank=True)
    
    # OWASP Top 10 Mapping
    owasp_category = models.CharField(max_length=100, blank=True) # e.g. "A01:2021-Broken Access Control"
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.alert} ({self.risk})"
