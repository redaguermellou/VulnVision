from django.urls import path
from . import views

app_name = 'scans'

urlpatterns = [
    path('', views.ScanListView.as_view(), name='scan_list'),
    path('create/', views.ScanCreateView.as_view(), name='scan_create'),
    path('<int:pk>/', views.ScanDetailView.as_view(), name='scan_detail'),
    path('<int:pk>/run/', views.ScanRunView.as_view(), name='scan_run'),
    path('<int:pk>/delete/', views.ScanDeleteView.as_view(), name='scan_delete'),
    path('<int:pk>/stop/', views.ScanStopView.as_view(), name='scan_stop'),
    path('<int:pk>/status/', views.ScanStatusView.as_view(), name='scan_status'),
    path('vulnerability-stats/', views.VulnerabilityStatsView.as_view(), name='vulnerability_stats'),
    path('trends/', views.VulnerabilityTrendsView.as_view(), name='trends'),
    path('report-builder/', views.ReportBuilderView.as_view(), name='report_builder'),
    path('owasp/', views.OWASPScanListView.as_view(), name='owasp_scan_list'),
    path('owasp/new/', views.OWASPScanCreateView.as_view(), name='owasp_scan_create'),
    path('owasp/<int:pk>/', views.OWASPScanDetailView.as_view(), name='owasp_scan_detail'),
]
