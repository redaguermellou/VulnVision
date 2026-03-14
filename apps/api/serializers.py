"""
VulnVision API Serializers
Covers User, Target, Scan, Vulnerability, and OWASPAlert.
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model

from apps.targets.models import Target
from apps.scans.models import Scan, Vulnerability, OWASPScan, OWASPAlert

User = get_user_model()


# ─────────────────────────────────────────────
# User
# ─────────────────────────────────────────────

class UserSerializer(serializers.ModelSerializer):
    """Public user representation – no password, no api_key."""
    class Meta:
        model = User
        fields = ['id', 'email', 'full_name', 'company', 'role', 'date_joined', 'is_active']
        read_only_fields = ['id', 'date_joined']


class UserProfileSerializer(serializers.ModelSerializer):
    """Full profile info returned on /api/me/."""
    role = serializers.CharField(source='user.role', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    full_name = serializers.CharField(source='user.full_name', read_only=True)
    api_key = serializers.CharField(source='user.api_key', read_only=True)

    class Meta:
        from apps.core.models import UserProfile
        model = UserProfile
        fields = ['email', 'full_name', 'role', 'api_key', 'bio', 'phone_number', 'location']


# ─────────────────────────────────────────────
# Target
# ─────────────────────────────────────────────

class TargetSerializer(serializers.ModelSerializer):
    vulnerability_count = serializers.IntegerField(
        source='vulnerabilities.count', read_only=True
    )
    scan_count = serializers.IntegerField(
        source='scans.count', read_only=True
    )

    class Meta:
        model = Target
        fields = [
            'id', 'name', 'address', 'target_type', 'description',
            'is_active', 'created_at', 'vulnerability_count', 'scan_count'
        ]
        read_only_fields = ['id', 'created_at', 'vulnerability_count', 'scan_count']


# ─────────────────────────────────────────────
# Vulnerability
# ─────────────────────────────────────────────

class VulnerabilitySerializer(serializers.ModelSerializer):
    target_name = serializers.CharField(source='target.name', read_only=True)
    scan_name = serializers.CharField(source='scan.name', read_only=True)
    cvss_severity = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'scan', 'scan_name', 'target', 'target_name',
            'title', 'description', 'severity', 'status',
            'component', 'evidence', 'remediation',
            'cve_id', 'cwe_id', 'cwe_category', 'owasp_category',
            'cvss_score', 'cvss_vector', 'cvss_severity',
            'has_exploit', 'exploit_refs',
            'created_at', 'updated_at', 'resolved_at', 'last_updated_db',
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'target_name', 'scan_name',
            'cvss_score', 'cvss_vector', 'has_exploit', 'exploit_refs',
            'last_updated_db',
        ]

    def get_cvss_severity(self, obj):
        """Returns human-readable severity label from CVSS score."""
        score = obj.cvss_score
        if score is None:
            return None
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score > 0:
            return 'Low'
        return 'None'


# ─────────────────────────────────────────────
# Scan
# ─────────────────────────────────────────────

class ScanSerializer(serializers.ModelSerializer):
    target_name = serializers.CharField(source='target.name', read_only=True)
    target_address = serializers.CharField(source='target.address', read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'name', 'scan_type', 'status', 'progress', 'current_phase',
            'target', 'target_name', 'target_address',
            'config',
            'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
            'created_at', 'started_at', 'completed_at', 'updated_at',
            'duration_seconds',
            'vulnerabilities',
        ]
        read_only_fields = [
            'id', 'status', 'progress', 'current_phase',
            'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
            'created_at', 'started_at', 'completed_at', 'updated_at',
            'duration_seconds', 'vulnerabilities', 'target_name', 'target_address',
        ]

    def get_duration_seconds(self, obj):
        d = obj.get_duration()
        return round(d.total_seconds()) if d else None


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight version for list endpoints (no nested vulnerabilities)."""
    target_name = serializers.CharField(source='target.name', read_only=True)
    duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'name', 'scan_type', 'status', 'progress',
            'target', 'target_name',
            'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
            'created_at', 'completed_at', 'duration_seconds',
        ]
        read_only_fields = fields

    def get_duration_seconds(self, obj):
        d = obj.get_duration()
        return round(d.total_seconds()) if d else None


# ─────────────────────────────────────────────
# OWASP
# ─────────────────────────────────────────────

class OWASPAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = OWASPAlert
        fields = [
            'id', 'alert', 'risk', 'reliability', 'url',
            'description', 'solution', 'param', 'evidence',
            'cweid', 'wascid', 'owasp_category', 'created_at',
        ]
        read_only_fields = fields


class OWASPScanSerializer(serializers.ModelSerializer):
    target_name = serializers.CharField(source='target.name', read_only=True)
    alerts = OWASPAlertSerializer(many=True, read_only=True)
    alert_count = serializers.IntegerField(source='alerts.count', read_only=True)

    class Meta:
        model = OWASPScan
        fields = [
            'id', 'target', 'target_name', 'scan_id', 'status', 'progress',
            'created_at', 'completed_at', 'alert_count', 'alerts',
        ]
        read_only_fields = [
            'id', 'scan_id', 'status', 'progress',
            'created_at', 'completed_at', 'target_name', 'alert_count', 'alerts',
        ]


# ─────────────────────────────────────────────
# Dashboard Stats
# ─────────────────────────────────────────────

class DashboardStatsSerializer(serializers.Serializer):
    total_targets = serializers.IntegerField()
    total_scans = serializers.IntegerField()
    total_vulnerabilities = serializers.IntegerField()
    critical_count = serializers.IntegerField()
    high_count = serializers.IntegerField()
    medium_count = serializers.IntegerField()
    low_count = serializers.IntegerField()
    open_vulns = serializers.IntegerField()
    resolved_vulns = serializers.IntegerField()
    vulns_with_exploits = serializers.IntegerField()
    recent_scans = ScanListSerializer(many=True)
