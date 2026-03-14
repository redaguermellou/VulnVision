"""
VulnVision REST API – Views & ViewSets
"""
from rest_framework import viewsets, status, filters
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.authentication import TokenAuthentication, SessionAuthentication

from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404

from apps.targets.models import Target
from apps.scans.models import Scan, Vulnerability, OWASPScan, OWASPAlert
from apps.scans.tasks import run_scan_task, refresh_vulnerability_db

from .serializers import (
    UserSerializer,
    TargetSerializer,
    ScanSerializer, ScanListSerializer,
    VulnerabilitySerializer,
    OWASPScanSerializer, OWASPAlertSerializer,
    DashboardStatsSerializer,
)
from .authentication import APIKeyAuthentication
from .pagination import StandardResultsPagination
from .throttles import (
    AnonBurstThrottle,
    UserSustainedThrottle,
    ScanCreateThrottle,
    AIQueryThrottle,
    ExportThrottle,
    RateLimitHeaderMixin,
)

User = get_user_model()


# ─────────────────────────────────────────────
# Shared Auth classes
# ─────────────────────────────────────────────

COMMON_AUTH = [TokenAuthentication, SessionAuthentication, APIKeyAuthentication]


# ─────────────────────────────────────────────
# /api/me/
# ─────────────────────────────────────────────

class CurrentUserView(APIView):
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# ─────────────────────────────────────────────
# Target ViewSet
# ─────────────────────────────────────────────

class TargetViewSet(RateLimitHeaderMixin, viewsets.ModelViewSet):
    serializer_class = TargetSerializer
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsPagination
    throttle_classes = [AnonBurstThrottle, UserSustainedThrottle]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'address', 'description']
    ordering_fields = ['created_at', 'name']
    ordering = ['-created_at']

    def get_queryset(self):
        return Target.objects.filter(user=self.request.user).annotate(
            vulnerability_count=Count('vulnerabilities', distinct=True),
            scan_count=Count('scans', distinct=True),
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['get'], url_path='vulnerabilities')
    def vulnerabilities(self, request, pk=None):
        """GET /api/targets/{id}/vulnerabilities/"""
        target = self.get_object()
        vulns = Vulnerability.objects.filter(target=target)
        page = self.paginate_queryset(vulns)
        if page is not None:
            return self.get_paginated_response(VulnerabilitySerializer(page, many=True).data)
        return Response(VulnerabilitySerializer(vulns, many=True).data)

    @action(detail=True, methods=['get'], url_path='scans')
    def scans(self, request, pk=None):
        """GET /api/targets/{id}/scans/"""
        target = self.get_object()
        scans = Scan.objects.filter(target=target, user=request.user)
        return Response(ScanListSerializer(scans, many=True).data)


# ─────────────────────────────────────────────
# Scan ViewSet
# ─────────────────────────────────────────────

class ScanViewSet(RateLimitHeaderMixin, viewsets.ModelViewSet):
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsPagination
    throttle_classes = [AnonBurstThrottle, UserSustainedThrottle]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'target__name']
    ordering_fields = ['created_at', 'status']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        return ScanSerializer

    def get_queryset(self):
        qs = Scan.objects.filter(user=self.request.user).select_related('target')
        # Optional filters via ?status=completed&type=nmap
        status_filter = self.request.query_params.get('status')
        type_filter = self.request.query_params.get('type')
        if status_filter:
            qs = qs.filter(status=status_filter)
        if type_filter:
            qs = qs.filter(scan_type=type_filter)
        return qs

    def perform_create(self, serializer):
        scan = serializer.save(user=self.request.user)
        # Auto-queue the scan task
        run_scan_task.delay(scan.id)

    def get_throttles(self):
        """Use ScanCreateThrottle only on POST (create)."""
        if self.action == 'create':
            return [ScanCreateThrottle()]
        return super().get_throttles()

    @action(detail=True, methods=['post'], url_path='run')
    def run(self, request, pk=None):
        """POST /api/scans/{id}/run/ – re-queue a stopped/failed scan."""
        scan = self.get_object()
        if scan.status not in ['pending', 'failed', 'stopped']:
            return Response(
                {'detail': 'Scan is already running or completed.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        run_scan_task.delay(scan.id)
        return Response({'detail': 'Scan queued.', 'scan_id': scan.id})

    @action(detail=True, methods=['get'], url_path='status')
    def scan_status(self, request, pk=None):
        """GET /api/scans/{id}/status/ – live scan status."""
        scan = self.get_object()
        return Response({
            'id': scan.id,
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.current_phase,
            'is_running': scan.status in ['running', 'pending'],
        })

    @action(detail=True, methods=['get'], url_path='vulnerabilities')
    def vulnerabilities(self, request, pk=None):
        """GET /api/scans/{id}/vulnerabilities/"""
        scan = self.get_object()
        vulns = scan.vulnerabilities.all()
        page = self.paginate_queryset(vulns)
        if page is not None:
            return self.get_paginated_response(VulnerabilitySerializer(page, many=True).data)
        return Response(VulnerabilitySerializer(vulns, many=True).data)


# ─────────────────────────────────────────────
# Vulnerability ViewSet
# ─────────────────────────────────────────────

class VulnerabilityViewSet(RateLimitHeaderMixin, viewsets.ModelViewSet):
    serializer_class = VulnerabilitySerializer
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsPagination
    throttle_classes = [AnonBurstThrottle, UserSustainedThrottle]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'cve_id', 'cwe_id', 'component']
    ordering_fields = ['severity', 'created_at', 'cvss_score']
    ordering = ['-created_at']

    def get_queryset(self):
        qs = Vulnerability.objects.filter(
            scan__user=self.request.user
        ).select_related('target', 'scan')

        severity = self.request.query_params.get('severity')
        vuln_status = self.request.query_params.get('status')
        has_exploit = self.request.query_params.get('has_exploit')
        target_id = self.request.query_params.get('target')

        if severity:
            qs = qs.filter(severity=severity)
        if vuln_status:
            qs = qs.filter(status=vuln_status)
        if has_exploit is not None:
            qs = qs.filter(has_exploit=has_exploit.lower() == 'true')
        if target_id:
            qs = qs.filter(target_id=target_id)

        return qs

    @action(detail=True, methods=['post'], url_path='refresh-db')
    def refresh_db(self, request, pk=None):
        """POST /api/vulnerabilities/{id}/refresh-db/ – queue NVD enrichment."""
        vuln = self.get_object()
        if not vuln.cve_id:
            return Response(
                {'detail': 'No CVE ID associated with this vulnerability.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        refresh_vulnerability_db.delay(vuln.id)
        return Response({'detail': f'NVD refresh queued for {vuln.cve_id}'})

    @action(detail=True, methods=['patch'], url_path='resolve')
    def resolve(self, request, pk=None):
        """PATCH /api/vulnerabilities/{id}/resolve/ – mark as resolved."""
        from django.utils import timezone
        vuln = self.get_object()
        vuln.status = 'resolved'
        vuln.resolved_at = timezone.now()
        vuln.save()
        return Response(VulnerabilitySerializer(vuln).data)


# ─────────────────────────────────────────────
# OWASP ViewSet
# ─────────────────────────────────────────────

class OWASPScanViewSet(RateLimitHeaderMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = OWASPScanSerializer
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsPagination
    throttle_classes = [AnonBurstThrottle, UserSustainedThrottle]

    def get_queryset(self):
        return OWASPScan.objects.filter(user=self.request.user).prefetch_related('alerts')

    @action(detail=True, methods=['get'], url_path='alerts')
    def alerts(self, request, pk=None):
        scan = self.get_object()
        risk = request.query_params.get('risk')
        qs = scan.alerts.all()
        if risk:
            qs = qs.filter(risk__iexact=risk)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(OWASPAlertSerializer(page, many=True).data)
        return Response(OWASPAlertSerializer(qs, many=True).data)


# ─────────────────────────────────────────────
# Dashboard Stats
# ─────────────────────────────────────────────

class DashboardStatsView(RateLimitHeaderMixin, APIView):
    authentication_classes = COMMON_AUTH
    permission_classes = [IsAuthenticated]
    throttle_classes = [UserSustainedThrottle]

    def get(self, request):
        user = request.user
        vulns = Vulnerability.objects.filter(scan__user=user)
        scans = Scan.objects.filter(user=user)
        targets = Target.objects.filter(user=user)

        data = {
            'total_targets': targets.count(),
            'total_scans': scans.count(),
            'total_vulnerabilities': vulns.count(),
            'critical_count': vulns.filter(severity='critical').count(),
            'high_count': vulns.filter(severity='high').count(),
            'medium_count': vulns.filter(severity='medium').count(),
            'low_count': vulns.filter(severity='low').count(),
            'open_vulns': vulns.filter(status='open').count(),
            'resolved_vulns': vulns.filter(status='resolved').count(),
            'vulns_with_exploits': vulns.filter(has_exploit=True).count(),
            'recent_scans': Scan.objects.filter(user=user).order_by('-created_at')[:5],
        }

        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)
