from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView, DetailView, CreateView, DeleteView, View, TemplateView
from django.db.models import Q, Count, Avg, F, Sum
from django.utils import timezone
from .models import Scan, Vulnerability, OWASPScan, OWASPAlert, Report, DataExport
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
        try:
            run_scan_task.delay(self.object.id)
            messages.success(self.request, f"Scan '{self.object.name}' has been queued.")
        except Exception as e:
            # Fallback for local development without Redis/Celery deployed
            import threading
            threading.Thread(target=run_scan_task, args=(self.object.id,)).start()
            messages.info(self.request, f"Scan '{self.object.name}' triggered via local background thread.")
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
            try:
                run_scan_task.delay(scan.id)
                messages.info(request, f"Scan '{scan.name}' has been queued.")
            except Exception as e:
                import threading
                threading.Thread(target=run_scan_task, args=(scan.id,)).start()
                messages.info(request, f"Scan '{scan.name}' started via background thread.")
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
        date_stats = vulns.values('created_at__date').annotate(day=F('created_at__date'), count=Count('id')).order_by('created_at__date')
        
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
            
            'severity_labels': [s['severity'] for s in severity_stats],
            'severity_data': [s['count'] for s in severity_stats],
            
            # Updated to match the key expectations in stats/trends
            'chart_severity_labels': [s['severity'].title() for s in severity_stats],
            'chart_severity_data': [s['count'] for s in severity_stats],
            'chart_status_labels': [s['status'].replace('_', ' ').title() for s in status_stats],
            'chart_status_data': [s['count'] for s in status_stats],
            'chart_date_labels': [str(s['created_at__date']) for s in date_stats],
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
        report_format = request.POST.get('format', 'pdf')
        report_type = request.POST.get('report_type', 'technical')
        target_id = request.POST.get('target')
        scan_id = request.POST.get('scan_id')
        severity = request.POST.get('severity')
        email_to = request.POST.get('email', '')
        
        vulns = Vulnerability.objects.filter(scan__user=user)
        if target_id:
            vulns = vulns.filter(target_id=target_id)
        if scan_id:
            vulns = vulns.filter(scan_id=scan_id)
        if severity:
            vulns = vulns.filter(severity=severity)
            
        if report_format == 'csv':
            csv_data = generate_csv_report(vulns)
            response = HttpResponse(csv_data, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="vulnvision_report.csv"'
            return response
        else:
            filters = {}
            if target_id: filters['target_id'] = target_id
            if scan_id: filters['scan_id'] = scan_id
            if severity: filters['severity'] = severity

            title = f"On-Demand {report_type.replace('_', ' ').title()} Report"
            if target_id:
                title += f" - Target: {Target.objects.get(id=target_id).name}"

            report = Report.objects.create(
                user=user,
                title=title,
                report_type=report_type,
                status='pending',
                filters=filters
            )
            
            try:
                from .tasks import generate_and_email_report
                generate_and_email_report.delay(report.id, email_to if email_to else None)
                messages.success(request, "Report is being generated securely in the background. Check the Reports page.")
            except Exception as e:
                import threading
                from .tasks import generate_and_email_report
                threading.Thread(target=generate_and_email_report, args=(report.id, email_to if email_to else None)).start()
                messages.success(request, "Report is being generated in a local thread. Check the Reports page soon.")
            return redirect('scans:report_list')


class ReportListView(LoginRequiredMixin, ListView):
    model = Report
    template_name = 'scans/report_list.html'
    context_object_name = 'reports'
    paginate_by = 15

    def get_queryset(self):
        return Report.objects.filter(user=self.request.user)

class ReportDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk):
        report = get_object_or_404(Report, pk=pk, user=request.user)
        if report.status == 'completed' and report.pdf_file:
            response = HttpResponse(report.pdf_file.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{report.pdf_file.name.split("/")[-1]}"'
            return response
        else:
            messages.error(request, "Report not ready or missing file.")
            return redirect('scans:report_list')

class ExportOptionsView(LoginRequiredMixin, TemplateView):
    template_name = 'scans/export_options.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['targets'] = Target.objects.filter(user=self.request.user)
        context['severity_choices'] = Vulnerability.SEVERITY_CHOICES
        context['scans'] = Scan.objects.filter(user=self.request.user).order_by('-created_at')[:50]
        return context

    def post(self, request, *args, **kwargs):
        export_range = request.POST.get('export_range', 'filtered')
        export_format = request.POST.get('format', 'csv')
        fields_str = request.POST.get('fields', '')
        fields_selection = [f.strip() for f in fields_str.split(',')] if fields_str else []
        
        filters = {}
        if export_range == 'filtered':
            target_id = request.POST.get('target')
            scan_id = request.POST.get('scan_id')
            severity = request.POST.get('severity')
            date_from = request.POST.get('date_from')
            date_to = request.POST.get('date_to')
            
            if target_id: filters['target'] = target_id
            if scan_id: filters['scan_id'] = scan_id
            if severity: filters['severity'] = severity
            if date_from: filters['date_from'] = date_from
            if date_to: filters['date_to'] = date_to

        export = DataExport.objects.create(
            user=request.user,
            export_range=export_range,
            export_format=export_format,
            status='pending',
            filters=filters,
            fields_selection=fields_selection
        )
        
        try:
            from .tasks import run_data_export
            run_data_export.delay(export.id)
            messages.success(request, f"Data export ({export_format.upper()}) is queued for processing.")
        except Exception as e:
            import threading
            from .tasks import run_data_export
            threading.Thread(target=run_data_export, args=(export.id,)).start()
            messages.success(request, f"Data export ({export_format.upper()}) is processing locally.")
        return redirect('scans:export_list')

class DataExportListView(LoginRequiredMixin, ListView):
    model = DataExport
    template_name = 'scans/export_list.html'
    context_object_name = 'exports'
    paginate_by = 15

    def get_queryset(self):
        return DataExport.objects.filter(user=self.request.user)

class DataExportDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk):
        export = get_object_or_404(DataExport, pk=pk, user=request.user)
        if export.status == 'completed' and export.file:
            content_types = {
                'csv': 'text/csv',
                'json': 'application/json',
                'excel': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
            content_type = content_types.get(export.export_format, 'application/octet-stream')
            response = HttpResponse(export.file.read(), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{export.file.name.split("/")[-1]}"'
            return response
        else:
            messages.error(request, "Export file is not ready or failed.")
            return redirect('scans:export_list')


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
        try:
            run_owasp_scan_task.delay(self.object.id)
            messages.success(self.request, "OWASP Top 10 Scan started successfully.")
        except Exception as e:
            import threading
            threading.Thread(target=run_owasp_scan_task, args=(self.object.id,)).start()
            messages.info(self.request, "OWASP scan triggered locally using background thread.")
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


# ─────────────────────────────────────────────
# External Vulnerability Database (VDB) Views
# ─────────────────────────────────────────────
from django.http import JsonResponse
from .tasks import refresh_vulnerability_db, daily_vulnerability_db_refresh

class VulnerabilityDetailView(LoginRequiredMixin, View):
    """Returns detailed vulnerability data (CVSS, exploits, NVD refs) as JSON for the modal."""
    def get(self, request, pk):
        vuln = get_object_or_404(Vulnerability, pk=pk, scan__user=request.user)
        data = {
            'id': vuln.id,
            'title': vuln.title,
            'description': vuln.description,
            'severity': vuln.severity,
            'cve_id': vuln.cve_id,
            'cwe_id': vuln.cwe_id,
            'cvss_score': vuln.cvss_score,
            'cvss_vector': vuln.cvss_vector,
            'has_exploit': vuln.has_exploit,
            'exploit_refs': vuln.exploit_refs,
            'component': vuln.component,
            'last_updated_db': vuln.last_updated_db.isoformat() if vuln.last_updated_db else None,
            # Pull safe subset of NVD description if available
            'nvd_description': (vuln.external_data.get('descriptions', [{}])[0].get('value', ''))
                               if vuln.external_data else '',
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}" if vuln.cve_id else '',
            'exploitdb_url': f"https://www.exploit-db.com/search?cve={vuln.cve_id}" if vuln.cve_id else '',
            'mitre_url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}" if vuln.cve_id else '',
        }
        return JsonResponse(data)


class RefreshVulnerabilityDBView(LoginRequiredMixin, View):
    """On-demand NVD enrichment for a single vulnerability (triggered by user from UI)."""
    def post(self, request, pk):
        vuln = get_object_or_404(Vulnerability, pk=pk, scan__user=request.user)
        if not vuln.cve_id:
            return JsonResponse({'status': 'error', 'message': 'No CVE ID for this vulnerability.'}, status=400)

        # Queue background task
        try:
            refresh_vulnerability_db.delay(vuln.id)
            return JsonResponse({'status': 'queued', 'message': f'Refresh queued for {vuln.cve_id}'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'Background worker unavailable.'}, status=503)


class TriggerDailyRefreshView(LoginRequiredMixin, View):
    """Staff-only view to manually kick off the daily database refresh task."""
    def post(self, request):
        if not request.user.is_staff:
            return JsonResponse({'status': 'error', 'message': 'Permission denied.'}, status=403)
        try:
            task = daily_vulnerability_db_refresh.delay()
            return JsonResponse({'status': 'queued', 'task_id': task.id})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'Background worker unavailable.'}, status=503)

