from celery import shared_task
from django.utils import timezone
from .models import Scan, Vulnerability
from .utils.nmap_scanner import NmapScanner
from .utils.nikto_scanner import NiktoScanner
from .utils.gobuster_scanner import GobusterScanner
from .utils.zap_scanner import ZAPScanner
import logging
import traceback

from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from django.conf import settings
from .utils.report_generator import generate_pdf_report
from django.core.files.base import ContentFile
import json
import csv
import pandas as pd
from io import StringIO, BytesIO

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def run_scan_task(self, scan_id):
    """
    Celery task to run a security scan asynchronously with real-time progress updates.
    """
    try:
        scan = Scan.objects.get(pk=scan_id)
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.progress = 5
        scan.current_phase = "Initializing scan engine..."
        scan.save()
        
        target_url = scan.target.url
        logger.info(f"Starting {scan.scan_type} scan for {target_url} (ID: {scan_id})")
        
        def update_progress(progress, phase=None):
            update_data = {'progress': progress}
            if phase:
                update_data['current_phase'] = phase
            Scan.objects.filter(pk=scan_id).update(**update_data)

        result = None
        # Determine engine and run
        if scan.scan_type == 'nikto':
            scanner = NiktoScanner()
            result = scanner.run_scan(target_url, config=scan.config, progress_callback=update_progress)
            if result.get('status') == 'success':
                _process_nikto_findings(scan, result['parsed_data'])
        
        elif scan.scan_type == 'gobuster':
            scanner = GobusterScanner()
            result = scanner.run_scan(target_url, config=scan.config, progress_callback=update_progress)
            if result.get('status') == 'success':
                _process_gobuster_findings(scan, result['parsed_data'])
                
        elif scan.scan_type == 'zap':
            scanner = ZAPScanner()
            alerts = scanner.run_full_scan(target_url, progress_callback=update_progress)
            if isinstance(alerts, dict) and 'error' in alerts:
                result = {'status': 'error', 'message': alerts['error']}
            else:
                result = {'status': 'success', 'parsed_data': alerts}
                _process_zap_findings(scan, alerts)
                
        else: # Default to Nmap
            scanner = NmapScanner()
            result = scanner.run_scan(target_url, scan_type=scan.scan_type, extra_args=scan.config, progress_callback=update_progress)
            if result.get('status') == 'success':
                _process_nmap_findings(scan, result['parsed_data'])

        # Finalize scan
        scan.refresh_from_db()
        if result:
            scan.config['raw_output'] = result.get('raw_output') or result.get('raw_data', '')

        if result and result.get('status') == 'success':
            scan.status = 'completed'
            scan.progress = 100
            scan.current_phase = "Scan completed successfully."
            scan.completed_at = timezone.now()
            scan.update_counts()
        else:
            scan.status = 'failed'
            scan.progress = 0
            error_msg = result.get('message', 'Unknown error') if result else 'Scan execution failed'
            scan.current_phase = f"Failed: {error_msg[:50]}..."
            scan.config['error'] = error_msg
            logger.error(f"Scan {scan_id} failed: {error_msg}")
            
        scan.save()
        return f"Scan {scan_id} {scan.status}"

    except Scan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found")
        return "Error: Scan not found"
    except Exception as e:
        logger.error(f"Task error: {str(e)}\n{traceback.format_exc()}")
        try:
            scan = Scan.objects.get(pk=scan_id)
            scan.status = 'failed'
            scan.config['error'] = str(e)
            scan.save()
        except:
            pass
        return f"Error: {str(e)}"

def _process_nmap_findings(scan, data):
    """Placeholder for Nmap findings processing - to be expanded"""
    if not data: return
    # Nmap integration already handles basic findings in previous steps
    # This would create Vulnerability objects from host/port data
    for host in data.get('hosts', []):
        for port in host.get('ports', []):
            if port.get('state') == 'open':
                service = port.get('service', {})
                Vulnerability.objects.create(
                    scan=scan,
                    target=scan.target,
                    title=f"Open Port: {port.get('portid')}/{port.get('protocol')}",
                    description=f"Service: {service.get('name')} {service.get('version') or ''}",
                    severity='info',
                    component=f"{port.get('portid')}/{port.get('protocol')}",
                    evidence=f"Service detection: {service}"
                )

def _process_nikto_findings(scan, data):
    """Converts Nikto parsed data into Vulnerability objects"""
    if not data: return
    for item in data.get('vulnerabilities', []):
        Vulnerability.objects.create(
            scan=scan,
            target=scan.target,
            title=f"Nikto: {item.get('id')} Found",
            description=item.get('message'),
            severity=item.get('severity', 'medium'),
            component=item.get('url'),
            evidence=f"Method: {item.get('method')}\nURL: {item.get('url')}",
            remediation="Refer to Nikto documentation for fix: https://cirt.net/Nikto2"
        )

def _process_gobuster_findings(scan, data):
    """Converts Gobuster parsed data into Vulnerability objects"""
    if not data: return
    for item in data:
        title = f"Discovered Path: {item.get('path')}"
        severity = item.get('severity', 'low')
        desc = f"Directory/File found at {item.get('path')}\nHTTP Status: {item.get('status')}\nSize: {item.get('size')} bytes"
        remediation = "If this is a sensitive directory or file, ensure it is not accessible publicly."
        
        Vulnerability.objects.create(
            scan=scan,
            target=scan.target,
            title=title,
            description=desc,
            severity=severity,
            component=item.get('path'),
            evidence=f"HTTP {item.get('status')} response received for path.",
            remediation=remediation
        )

def _process_zap_findings(scan, data):
    """Converts ZAP parsed data into Vulnerability objects"""
    if not data: return
    for item in data:
        cwe_id = item.get('cweid', '')
        severity_map = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'info'}
        zap_risk = item.get('risk', 'Informational')
        severity = severity_map.get(zap_risk, 'info')
        
        Vulnerability.objects.create(
            scan=scan,
            target=scan.target,
            title=f"ZAP: {item.get('alert', 'Unknown Finding')}",
            description=item.get('description', ''),
            severity=severity,
            component=item.get('url', ''),
            evidence=item.get('evidence', ''),
            remediation=item.get('solution', ''),
            cwe_id=cwe_id,
        )

@shared_task
def send_weekly_reports_task():
    """
    Weekly task to send security reports to all active users.
    """
    from .models import Vulnerability # Lazy import to avoid circular dependency
    users = User.objects.filter(is_active=True)
    today = timezone.now()
    
    for user in users:
        vulns = Vulnerability.objects.filter(scan__user=user)
        if not vulns.exists():
            continue
            
        context = {
            'user': user,
            'vulnerabilities': vulns.order_by('-severity')[:50],
            'total_count': vulns.count(),
            'critical_count': vulns.filter(severity='critical').count(),
            'high_count': vulns.filter(severity='high').count(),
            'generated_at': today,
            'current_year': today.year,
            'site_url': 'http://localhost:8000'
        }
        
        email_body = render_to_string('emails/weekly_report.html', context)
        pdf_content = generate_pdf_report('reports/vulnerability_detail.html', context)
        
        email = EmailMessage(
            subject=f"VulnVision Weekly Security Report - {today.strftime('%Y-%m-%d')}",
            body=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = "html"
        
        if pdf_content:
            email.attach(f"security_report_{today.strftime('%Y%m%d')}.pdf", pdf_content, 'application/pdf')
            
        email.send()
        
    return f"Sent reports to users"

from .utils.zap_scanner import ZAPScanner

@shared_task
def run_owasp_scan_task(owasp_scan_id):
    from .models import OWASPScan, OWASPAlert
    try:
        owasp_scan = OWASPScan.objects.get(id=owasp_scan_id)
        owasp_scan.status = 'running'
        owasp_scan.save()
        
        scanner = ZAPScanner()
        
        def progress_cb(progress, phase):
            owasp_scan.progress = progress
            owasp_scan.status = phase
            owasp_scan.save()

        alerts = scanner.run_full_scan(owasp_scan.target.address, progress_callback=progress_cb)
        
        if isinstance(alerts, dict) and 'error' in alerts:
            owasp_scan.status = f"Failed: {alerts['error']}"
            owasp_scan.save()
            return

        # Process findings
        for alert_data in alerts:
            cwe_id = alert_data.get('cweid', '')
            category = scanner.get_owasp_category(cwe_id)
            
            OWASPAlert.objects.create(
                owasp_scan=owasp_scan,
                alert=alert_data.get('alert', 'Unknown'),
                risk=alert_data.get('risk', 'Informational'),
                reliability=alert_data.get('reliability', 'N/A'),
                url=alert_data.get('url', ''),
                description=alert_data.get('description', ''),
                solution=alert_data.get('solution', ''),
                param=alert_data.get('param', ''),
                evidence=alert_data.get('evidence', ''),
                cweid=cwe_id,
                wascid=alert_data.get('wascid', ''),
                owasp_category=category
            )

        owasp_scan.status = 'completed'
        owasp_scan.progress = 100
        owasp_scan.completed_at = timezone.now()
        owasp_scan.save()

    except OWASPScan.DoesNotExist:
        logger.error(f"OWASPScan {owasp_scan_id} not found")
    except Exception as e:
        logger.error(f"Error in run_owasp_scan_task: {str(e)}")
        if 'owasp_scan' in locals():
            owasp_scan.status = 'failed'
            owasp_scan.save()


# ─────────────────────────────────────────────
# External Vulnerability Database (VDB) Tasks
# ─────────────────────────────────────────────

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def refresh_vulnerability_db(self, vuln_id):
    """
    Celery task to refresh NVD/Exploit-DB data for a single Vulnerability.
    Retries up to 3 times on network errors.
    """
    from .utils.vdb_service import VDBService
    try:
        service = VDBService()
        success, message = service.update_vulnerability(vuln_id)
        logger.info(f"[VDB] Vuln #{vuln_id}: {message}")
        return {'vuln_id': vuln_id, 'success': success, 'message': message}
    except Exception as exc:
        logger.error(f"[VDB] Error refreshing vuln #{vuln_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task
def daily_vulnerability_db_refresh():
    """
    Celery Beat task: runs every day and queues individual refresh tasks
    for all Vulnerability records that have a CVE ID and haven't been
    updated in the last 24 hours.
    """
    from django.db.models import Q
    from datetime import timedelta

    cutoff = timezone.now() - timedelta(hours=24)
    vulns = Vulnerability.objects.exclude(cve_id="").filter(
        Q(last_updated_db__isnull=True) | Q(last_updated_db__lt=cutoff)
    ).values_list('id', flat=True)

    queued = 0
    for vuln_id in vulns:
        refresh_vulnerability_db.apply_async(
            args=[vuln_id],
            countdown=queued * 2  # stagger by 2 sec each to respect NVD rate limits
        )
        queued += 1

    logger.info(f"[VDB] Daily refresh: queued {queued} vulnerability update tasks.")
    return f"Queued {queued} tasks"


@shared_task
def enrich_new_scan_vulns(scan_id):
    """
    Called right after a scan completes to auto-enrich any findings that
    have CVE IDs (populated by the scanner) with CVSS scores and exploit info.
    """
    try:
        scan = Scan.objects.get(pk=scan_id)
        vulns_with_cve = scan.vulnerabilities.exclude(cve_id="")
        queued = 0
        for vuln in vulns_with_cve:
            refresh_vulnerability_db.delay(vuln.id)
            queued += 1
        logger.info(f"[VDB] Enrich scan #{scan_id}: queued {queued} tasks.")
        return f"Queued {queued} enrichment tasks for scan #{scan_id}"
    except Scan.DoesNotExist:
        logger.error(f"[VDB] Scan #{scan_id} not found for enrichment.")
        return "Error: scan not found"

@shared_task(bind=True)
def generate_and_email_report(self, report_id, email_to=None):
    """
    Celery task to generate a PDF report asynchronously and optionally email it.
    """
    from .models import Report, Vulnerability
    try:
        report = Report.objects.get(id=report_id)
        report.status = 'generating'
        report.save()

        # Gather data based on report configuration
        vulns = Vulnerability.objects.filter(scan__user=report.user)
        
        target_id = report.filters.get('target_id')
        scan_id = report.filters.get('scan_id')
        severity = report.filters.get('severity')
        
        if target_id:
            vulns = vulns.filter(target_id=target_id)
        if scan_id:
            vulns = vulns.filter(scan_id=scan_id)
        if severity:
            vulns = vulns.filter(severity=severity)
            
        context = {
            'report': report,
            'vulnerabilities': vulns.order_by('-severity'),
            'total_count': vulns.count(),
            'critical_count': vulns.filter(severity='critical').count(),
            'high_count': vulns.filter(severity='high').count(),
            'medium_count': vulns.filter(severity='medium').count(),
            'low_count': vulns.filter(severity='low').count(),
            'info_count': vulns.filter(severity='info').count(),
            'generated_at': timezone.now(),
            'user': report.user,
        }

        # Determine template
        template_map = {
            'executive': 'reports/executive_summary.html',
            'technical': 'reports/technical_report.html',
            'compliance_pci': 'reports/compliance_pci.html',
            'compliance_iso': 'reports/compliance_iso.html',
        }
        template_src = template_map.get(report.report_type, 'reports/technical_report.html')

        pdf_bytes = generate_pdf_report(template_src, context)
        
        if pdf_bytes:
            filename = f"report_{report.report_type}_{timezone.now().strftime('%Y%m%d%H%M%S')}.pdf"
            report.pdf_file.save(filename, ContentFile(pdf_bytes))
            report.file_size = len(pdf_bytes)
            report.status = 'completed'
            report.completed_at = timezone.now()
            report.save()
            
            # Send Email if requested
            if email_to:
                subject = f"VulnVision {report.get_report_type_display()} - {report.title}"
                body = f"Hello,\n\nYour requested report '{report.title}' has been generated.\n\nPlease find the attached PDF document."
                email = EmailMessage(
                    subject=subject,
                    body=body,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[email_to],
                )
                email.attach(filename, pdf_bytes, 'application/pdf')
                email.send()
                
            return f"Report {report_id} generated successfully"
        else:
            report.status = 'failed'
            report.error_message = "PDF generation returned empty"
            report.save()
            return f"Report {report_id} failed: PDF generation failed"

    except Exception as e:
        logger.error(f"Report generation error: {str(e)}\n{traceback.format_exc()}")
        try:
            report = Report.objects.get(id=report_id)
            report.status = 'failed'
            report.error_message = str(e)
            report.save()
        except:
            pass
        return f"Error: {str(e)}"

@shared_task(bind=True)
def run_data_export(self, export_id):
    """
    Celery task to generate CSV, Excel, or JSON data exports asynchronously.
    """
    from .models import DataExport, Scan, Vulnerability
    try:
        export = DataExport.objects.get(id=export_id)
        export.status = 'processing'
        export.save()

        # Gather Data
        data_list = []
        if export.export_range == 'all_scans':
            scans = Scan.objects.filter(user=export.user)
            for scan in scans:
                data_list.append({
                    'ID': scan.id,
                    'Name': scan.name,
                    'Target': scan.target.name,
                    'Type': scan.get_scan_type_display(),
                    'Status': scan.get_status_display(),
                    'Critical': scan.critical_count,
                    'High': scan.high_count,
                    'Medium': scan.medium_count,
                    'Low': scan.low_count,
                    'Created At': scan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                })
        else:
            # Vulnerabilities (all or filtered)
            vulns = Vulnerability.objects.filter(scan__user=export.user)
            
            if export.export_range == 'filtered':
                target_id = export.filters.get('target')
                scan_id = export.filters.get('scan_id')
                severity = export.filters.get('severity')
                date_from = export.filters.get('date_from')
                date_to = export.filters.get('date_to')
                
                if target_id: vulns = vulns.filter(target_id=target_id)
                if scan_id: vulns = vulns.filter(scan_id=scan_id)
                if severity: vulns = vulns.filter(severity=severity)
                if date_from: vulns = vulns.filter(created_at__date__gte=date_from)
                if date_to: vulns = vulns.filter(created_at__date__lte=date_to)

            # Build data with selected fields or all
            fields = export.fields_selection if export.fields_selection else [
                'ID', 'Title', 'Severity', 'Target', 'Scan', 'Status', 
                'Component', 'CVE ID', 'CWE ID', 'Created At'
            ]
            
            for vuln in vulns:
                item = {}
                v_data = {
                    'ID': vuln.id,
                    'Title': vuln.title,
                    'Severity': vuln.get_severity_display(),
                    'Target': vuln.target.name,
                    'Scan': vuln.scan.name,
                    'Status': vuln.get_status_display(),
                    'Component': vuln.component,
                    'CVE ID': vuln.cve_id,
                    'CWE ID': vuln.cwe_id,
                    'Description': vuln.description,
                    'Remediation': vuln.remediation,
                    'Created At': vuln.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                }
                for f in fields:
                    if f in v_data:
                        item[f] = v_data[f]
                data_list.append(item)

        # Ensure we have data
        if not data_list:
            data_list = [{'Info': 'No data found matching criteria'}]

        df = pd.DataFrame(data_list)
        file_bytes = None
        filename = f"export_{export.id}_{export.export_range}_{timezone.now().strftime('%Y%m%d%H%M')}."
        
        if export.export_format == 'csv':
            filename += 'csv'
            csv_buffer = StringIO()
            df.to_csv(csv_buffer, index=False)
            file_bytes = csv_buffer.getvalue().encode('utf-8')
            
        elif export.export_format == 'excel':
            filename += 'xlsx'
            excel_buffer = BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Export Data')
            file_bytes = excel_buffer.getvalue()
            
        elif export.export_format == 'json':
            filename += 'json'
            json_buffer = StringIO()
            df.to_json(json_buffer, orient='records', indent=4)
            file_bytes = json_buffer.getvalue().encode('utf-8')

        if file_bytes:
            export.file.save(filename, ContentFile(file_bytes))
            export.file_size = len(file_bytes)
            export.status = 'completed'
            export.completed_at = timezone.now()
            export.save()
            return f"Export {export_id} completed successfully"
        else:
            raise ValueError("File generation failed")

    except Exception as e:
        logger.error(f"Data Export error: {str(e)}\n{traceback.format_exc()}")
        try:
            export = DataExport.objects.get(id=export_id)
            export.status = 'failed'
            export.error_message = str(e)
            export.save()
        except:
            pass
        return f"Error: {str(e)}"

