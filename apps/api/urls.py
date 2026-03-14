"""
VulnVision API – URL routing
Base path: /api/v1/
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

from .views import (
    CurrentUserView,
    TargetViewSet,
    ScanViewSet,
    VulnerabilityViewSet,
    OWASPScanViewSet,
    DashboardStatsView,
)

app_name = 'api'

router = DefaultRouter()
router.register(r'targets',         TargetViewSet,         basename='target')
router.register(r'scans',           ScanViewSet,           basename='scan')
router.register(r'vulnerabilities', VulnerabilityViewSet,  basename='vulnerability')
router.register(r'owasp-scans',     OWASPScanViewSet,      basename='owasp-scan')

urlpatterns = [
    # ── Router-generated endpoints ──────────────────────────
    path('', include(router.urls)),

    # ── Auth ────────────────────────────────────────────────
    path('auth/token/',  obtain_auth_token,   name='api_token_auth'),
    path('auth/me/',     CurrentUserView.as_view(), name='current_user'),

    # ── Dashboard ───────────────────────────────────────────
    path('dashboard/', DashboardStatsView.as_view(), name='dashboard_stats'),

    # ── OpenAPI / Docs ──────────────────────────────────────
    path('schema/',         SpectacularAPIView.as_view(),         name='schema'),
    path('docs/swagger/',   SpectacularSwaggerView.as_view(url_name='api:schema'), name='swagger_ui'),
    path('docs/redoc/',     SpectacularRedocView.as_view(url_name='api:schema'),   name='redoc'),
]
