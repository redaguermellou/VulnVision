from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView, CreateView, DeleteView, View
from django.db.models import Q, Count, Avg, F, Sum
from django.utils import timezone
from .models import Scan, Vulnerability, OWASPScan, OWASPAlert
from apps.targets.models import Target
from .tasks import run_scan_task

class ScanListView(LoginRequiredMixin, ListView):
    model = Scan
    template_name = 'scans/scan_list.html'
    context_object_name = 'scans'
    paginate_by = 15

    def get_queryset(self):
        queryset = Scan.objects.filter(user=self.request.user)
        
        # Search
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query) | Q(target__name__icontains=query)
            )
            
        # Filters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
            
        scan_type = self.request.GET.get('type')
        if scan_type:
            queryset = queryset.filter(scan_type=scan_type)
            
        date_from = self.request.GET.get('date_from')
        date_to = self.request.GET.get('date_to')
        if date_from:
            queryset = queryset.filter(created_at__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__date__lte=date_to)
            
        return queryset

class ScanDetailView(LoginRequiredMixin, DetailView):
    model = Scan
    template_name = 'scans/scan_detail.html'
    context_object_name = 'scan'

class ScanCreateView(LoginRequiredMixin, CreateView):
    model = Scan
    fields = ['target', 'name', 'scan_type', 'config']
    template_name = 'scans/scan_form.html'
    success_url = reverse_lazy('scans:scan_list')

    def get_form(self, *args, **kwargs):
        form = super().get_form(*args, **kwargs)
        # Only allow user's own targets
        form.fields['target'].queryset = Target.objects.filter(user=self.request.user, is_active=True)
        return form

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        # Automatically trigger the scan task asynchronously
        run_scan_task.delay(self.object.id)
        messages.success(self.request, f"Scan '{self.object.name}' has been queued.")
        return response

class ScanDeleteView(LoginRequiredMixin, DeleteView):
    model = Scan
    template_name = 'scans/scan_confirm_delete.html'
    success_url = reverse_lazy('scans:scan_list')

    def delete(self, request, *args, **kwargs):
        scan = self.get_object()
        messages.success(self.request, f"Scan '{scan.name}' deleted.")
        return super().delete(request, *args, **kwargs)

class ScanStopView(LoginRequiredMixin, View):
    def post(self, request, pk):
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        if scan.status == 'running':
            scan.status = 'stopped'
            scan.completed_at = timezone.now()
            scan.save()
            messages.warning(request, f"Scan '{scan.name}' has been stopped.")
        return redirect('scans:scan_detail', pk=pk)

class ScanRunView(LoginRequiredMixin, View):
    def post(self, request, pk):
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        if scan.status in ['pending', 'failed', 'stopped']:
            # Run scan asynchronously with Celery
            run_scan_task.delay(scan.id)
            messages.info(request, f"Scan '{scan.name}' has been queued.")
        else:
            messages.error(request, "Scan is already running or completed.")
            
        return redirect('scans:scan_detail', pk=pk)

from django.http import JsonResponse

class ScanStatusView(LoginRequiredMixin, View):
    def get(self, request, pk):
        scan = get_object_or_404(Scan, pk=pk, user=request.user)
        return JsonResponse({
            'status': scan.status,
            'progress': scan.progress,
            'phase': scan.current_phase,
            'critical': scan.critical_count,
            'high': scan.high_count,
            'medium': scan.medium_count,
            'low': scan.low_count,
            'info': scan.info_count,
            'total': scan.vulnerabilities.count(),
            'is_running': scan.status in ['running', 'pending']
        })

from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

class VulnerabilityStatsView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        vulns = Vulnerability.objects.filter(scan__user=user)
        
        # Filtering
        severity = request.GET.get('severity')
        target_id = request.GET.get('target')
        cwe_cat = request.GET.get('cwe')
        date_start = request.GET.get('date_start')
        date_end = request.GET.get('date_end')
        
        if severity: vulns = vulns.filter(severity=severity)
        if target_id: vulns = vulns.filter(target_id=target_id)
        if cwe_cat: vulns = vulns.filter(cwe_category=cwe_cat)
        if date_start: vulns = vulns.filter(created_at__date__gte=date_start)
        if date_end: vulns = vulns.filter(created_at__date__lte=date_end)
        
        # Aggregations
        severity_stats = vulns.values('severity').annotate(count=Count('id'))
        target_stats = vulns.values('target__name').annotate(count=Count('id')).order_by('-count')[:10]
        cwe_stats = vulns.values('cwe_category').annotate(count=Count('id')).order_by('-count')[:10]
        status_stats = vulns.values('status').annotate(count=Count('id'))
        
        # Top 10 vulnerabilities
        top_vulns = vulns.values('title', 'severity').annotate(count=Count('id')).order_by('-count')[:10]
        
        # Recently discovered (Last 7 days)
        last_7_days = timezone.now() - timedelta(days=7)
        recent_vulns = vulns.filter(created_at__gte=last_7_days).order_by('-created_at')[:20]
        
        # Heatmap data (Date discovered)
        date_stats = vulns.extra(select={'day': "date(created_at)"}).values('day').annotate(count=Count('id')).order_by('day')
        
        # Chart Labels and Data
        context = {
            'vulns': vulns,
            'targets': Target.objects.filter(user=user),
            'cwe_categories': vulns.exclude(cwe_category__isnull=True).values_list('cwe_category', flat=True).distinct(),
            'severity_choices': Vulnerability.SEVERITY_CHOICES,
            
            'severity_stats': severity_stats,
            'target_stats': target_stats,
            'cwe_stats': cwe_stats,
            'status_stats': status_stats,
            'top_vulns': top_vulns,
            'recent_vulns': recent_vulns,
            
            # Chart Data
            'chart_severity_labels': [s['severity'] for s in severity_stats],
            'chart_severity_data': [s['count'] for s in severity_stats],
            'chart_status_labels': [s['status'] for s in status_stats],
            'chart_status_data': [s['count'] for s in status_stats],
            'chart_date_labels': [str(s['day']) for s in date_stats],
            'chart_date_data': [s['count'] for s in date_stats],
            'chart_target_labels': [s['target__name'] for s in target_stats],
            'chart_target_data': [s['count'] for s in target_stats],
        }
        
        return render(request, 'scans/vulnerability_stats.html', context)

from django.db.models.functions import TruncMonth, TruncYear
from .utils.report_generator import generate_pdf_report, generate_csv_report
from django.http import HttpResponse

class VulnerabilityTrendsView(LoginRequiredMixin, View):
    def get(self, request):
        user = request.user
        vulns = Vulnerability.objects.filter(scan__user=user)
        
        # 1. MoM Trends (Findings by month)
        mom_stats = vulns.annotate(month=TruncMonth('created_at')).values('month')\
            .annotate(count=Count('id')).order_by('month')
            
        chart_mom_labels = [s['month'].strftime('%b %Y') for s in mom_stats]
        chart_mom_data = [s['count'] for s in mom_stats]
        
        # 2. Avg Severity Score Trend
        # Map severity to numerical score for trending
        severity_map = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        # This is a bit complex for pure ORM, might be easier with a loop or list comprehension
        
        # 3. Time to Remediate Trend
        resolved_vulns = vulns.filter(status='resolved', resolved_at__isnull=False)
        ttr_stats = resolved_vulns.annotate(month=TruncMonth('created_at')).values('month')\
            .annotate(avg_ttr=Avg(F('resolved_at') - F('created_at'))).order_by('month')
            
        chart_ttr_labels = [s['month'].strftime('%b %Y') for s in ttr_stats]
        chart_ttr_data = [s['avg_ttr'].total_seconds() / 3600 if s['avg_ttr'] else 0 for s in ttr_stats]

        context = {
            'chart_mom_labels': chart_mom_labels,
            'chart_mom_data': chart_mom_data,
            'chart_ttr_labels': chart_ttr_labels,
            'chart_ttr_data': chart_ttr_data,
        }
        return render(request, 'scans/trends.html', context)

class ReportBuilderView(LoginRequiredMixin, View):
    def get(self, request):
        context = {
            'targets': Target.objects.filter(user=request.user),
            'severity_choices': Vulnerability.SEVERITY_CHOICES
        }
        return render(request, 'scans/report_builder.html', context)
        
    def post(self, request):
        user = request.user
        report_type = request.POST.get('format', 'pdf')
        target_id = request.POST.get('target')
        severity = request.POST.get('severity')
        
        vulns = Vulnerability.objects.filter(scan__user=user)
        if target_id:
            vulns = vulns.filter(target_id=target_id)
        if severity:
            vulns = vulns.filter(severity=severity)
            
        if report_type == 'csv':
            csv_data = generate_csv_report(vulns)
            response = HttpResponse(csv_data, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="vulnvision_report.csv"'
            return response
        else:
            # Generate PDF
            context = {
                'vulnerabilities': vulns,
                'user': user,
                'target': Target.objects.get(id=target_id) if target_id else None,
                'generated_at': timezone.now(),
                'total_count': vulns.count(),
                'critical_count': vulns.filter(severity='critical').count(),
                'high_count': vulns.filter(severity='high').count()
            }
            pdf = generate_pdf_report('reports/vulnerability_detail.html', context)
            if pdf:
                response = HttpResponse(pdf, content_type='application/pdf')
                response['Content-Disposition'] = 'attachment; filename="vulnvision_report.pdf"'
                return response
            return HttpResponse("Error generating PDF", status=500)

from .tasks import run_owasp_scan_task

class OWASPScanListView(LoginRequiredMixin, ListView):
    model = OWASPScan
    template_name = 'scans/owasp_scan_list.html'
    context_object_name = 'scans'

    def get_queryset(self):
        return OWASPScan.objects.filter(user=self.request.user)

class OWASPScanCreateView(LoginRequiredMixin, CreateView):
    model = OWASPScan
    fields = ['target']
    template_name = 'scans/owasp_scan_form.html'
    success_url = reverse_lazy('scans:owasp_scan_list')

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        run_owasp_scan_task.delay(self.object.id)
        messages.success(self.request, "OWASP Top 10 Scan started successfully.")
        return response

class OWASPScanDetailView(LoginRequiredMixin, DetailView):
    model = OWASPScan
    template_name = 'scans/owasp_scan_detail.html'
    context_object_name = 'scan'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Group alerts by OWASP category for the dashboard
        alerts = self.object.alerts.all()
        categories = alerts.values('owasp_category').annotate(count=Count('id')).order_by('owasp_category')
        
        context['category_stats'] = categories
        context['alerts'] = alerts
        return context
