from django.utils import timezone
from ..models import Scan, Vulnerability
from .nmap_scanner import NmapScanner
from .nikto_scanner import NiktoScanner
from .gobuster_scanner import GobusterScanner
import json
import logging

logger = logging.getLogger(__name__)

def run_scan_task(scan_id):
    """
    Background task simulation to run appropriate scanner based on scan type.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.save()
        
        target_url = scan.target.url
        # Clean URL for hostname mapping
        target_host = target_url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        
        result = None
        
        # Determine engine
        if scan.scan_type == 'nikto':
            scanner = NiktoScanner()
            result = scanner.run_scan(target_url, config=scan.config)
            if result['status'] == 'success':
                _process_nikto_findings(scan, result['parsed_data'])
        
        elif scan.scan_type == 'gobuster':
            scanner = GobusterScanner()
            result = scanner.run_scan(target_url, config=scan.config)
            if result['status'] == 'success':
                _process_gobuster_findings(scan, result['parsed_data'])
                
        else: # Default to Nmap for now
            scanner = NmapScanner()
            scan_type = scan.scan_type
            if scan_type == 'nmap':
                scan_type = 'quick'
            
            result = scanner.run_scan(target_host, scan_type=scan_type)
            if result['status'] == 'success':
                _process_nmap_findings(scan, result['parsed_data'])

        if result and result['status'] == 'success':
            scan.status = 'completed'
            scan.update_counts() # New method in Scan model
        else:
            scan.status = 'failed'
            scan.config['error'] = result.get('message', 'Scanner execution failed') if result else 'Undefined scanner'
            
        scan.completed_at = timezone.now()
        scan.save()
        return True
        
    except Scan.DoesNotExist:
        logger.error(f"Scan {scan_id} not found.")
        return False
    except Exception as e:
        logger.error(f"Error processing scan {scan_id}: {e}")
        if 'scan' in locals():
            scan.status = 'failed'
            scan.config['error'] = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        return False

def _process_nmap_findings(scan, data):
    """Converts Nmap parsed data into Vulnerability objects"""
    if not data: return
    
    for host in data.get('hosts', []):
        for port in host.get('ports', []):
            if port.get('state') == 'open':
                service = port.get('service', {})
                title = f"Open Port: {port.get('portid')}/{port.get('protocol')}"
                if service.get('name'):
                    title += f" ({service.get('name')})"
                
                desc = f"Service: {service.get('product', 'Unknown')} {service.get('version', '')}\n"
                desc += f"Extra Info: {service.get('extrainfo', 'None')}"
                
                Vulnerability.objects.create(
                    scan=scan,
                    target=scan.target,
                    title=title,
                    description=desc,
                    severity='info', # Nmap basic port findings are info
                    component=f"{port.get('portid')}/{port.get('protocol')}",
                    evidence=f"Port state: {port.get('state')}"
                )

def _process_nikto_findings(scan, data):
    """Converts Nikto parsed data into Vulnerability objects"""
    if not data: return
    
    for item in data.get('vulnerabilities', []):
        Vulnerability.objects.create(
            scan=scan,
            target=scan.target,
            title=f"Nikto Finding: {item.get('id')}",
            description=item.get('message'),
            severity=item.get('severity', 'info'),
            component=item.get('url', 'N/A'),
            evidence=f"Method: {item.get('method')}\nURL: {item.get('url')}",
            remediation="Refer to Nikto documentation for fix: https://cirt.net/Nikto2"
        )

def _process_gobuster_findings(scan, data):
    """Converts Gobuster parsed data into Vulnerability objects"""
    if not data: return
    
    for item in data:
        title = f"Discovered Path: {item.get('path')}"
        severity = item.get('severity', 'low')
        
        desc = f"Directory/File found at {item.get('path')}\n"
        desc += f"HTTP Status: {item.get('status')}\n"
        desc += f"Size: {item.get('size')} bytes"
        
        remediation = "If this is a sensitive directory or file, ensure it is not accessible publicly by using .htaccess, web server configuration, or moving it out of the web root."
        if severity in ['critical', 'high']:
            remediation = "IMMEDIATE ACTION REQUIRED: This sensitive path is exposed. Restrict access immediately."

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
