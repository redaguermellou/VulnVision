from celery import shared_task
from django.utils import timezone
from .models import Scan, Vulnerability
from .utils.nmap_scanner import NmapScanner
from .utils.nikto_scanner import NiktoScanner
from .utils.gobuster_scanner import GobusterScanner
import logging
import traceback

from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from django.conf import settings
from .utils.report_generator import generate_pdf_report

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
                
        else: # Default to Nmap
            scanner = NmapScanner()
            result = scanner.run_scan(target_url, scan_type=scan.scan_type, extra_args=scan.config, progress_callback=update_progress)
            if result.get('status') == 'success':
                _process_nmap_findings(scan, result['parsed_data'])

        # Finalize scan
        scan.refresh_from_db()
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
