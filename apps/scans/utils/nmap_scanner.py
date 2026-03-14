import subprocess
import xml.etree.ElementTree as ET
import os
import tempfile
import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, binary_path='nmap'):
        self.binary_path = binary_path

    def _get_base_args(self, scan_type):
        """Returns nmap arguments based on scan type"""
        args = ['-oX', '-'] # Output to XML directed to stdout
        
        if scan_type == 'quick':
            args.extend(['-F']) # Fast scan (top 100 ports)
        elif scan_type == 'full':
            args.extend(['-p-']) # All 65535 ports
        elif scan_type == 'service':
            args.extend(['-sV']) # Service version detection
        elif scan_type == 'os':
            args.extend(['-O', '--osscan-guess']) # OS detection
        elif scan_type == 'script':
            args.extend(['-sC']) # Default scripts
        elif scan_type == 'comprehensive':
            args.extend(['-sS', '-sV', '-O', '-sC']) # Standard comprehensive scan
            
        return args

    def run_scan(self, target, scan_type='quick', extra_args=None, progress_callback=None):
        """
        Runs nmap scan against a target with real-time progress reporting.
        """
        command = [self.binary_path]
        command.extend(self._get_base_args(scan_type))
        command.extend(['--stats-every', '2s'])
        
        if extra_args:
            if isinstance(extra_args, list):
                command.extend(extra_args)
            elif isinstance(extra_args, dict):
                pass
            else:
                command.append(str(extra_args))
                
        command.append(target)
        
        logger.info(f"Running nmap command: {' '.join(command)}")
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            full_output = []
            progress_pattern = re.compile(r'About ([\d\.]+)% done')
            phase_pattern = re.compile(r'undergoing ([\w\s]+)')
            
            if process.stdout:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        full_output.append(line)
                        if progress_callback:
                            prog_match = progress_pattern.search(line)
                            phase_match = phase_pattern.search(line)
                            if prog_match or phase_match:
                                progress = float(prog_match.group(1)) if prog_match else 0
                                phase = phase_match.group(1).strip() if phase_match else "Scanning..."
                                progress_callback(int(progress), f"Nmap: {phase}")

            process.wait(timeout=60)
            stdout = "".join(full_output)
            
            if process.returncode != 0:
                # If it failed but we have XML, it might be partial
                if '<?xml' in stdout and '</nmaprun>' in stdout:
                     return {
                        'status': 'success',
                        'raw_xml': stdout,
                        'parsed_data': self.parse_xml(stdout)
                    }

                return {
                    'status': 'error',
                    'message': f"Nmap exited with code {process.returncode}",
                    'raw_output': stdout
                }
                
            return {
                'status': 'success',
                'raw_xml': stdout,
                'parsed_data': self.parse_xml(stdout)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def parse_xml(self, xml_content):
        """Parses nmap XML output safely"""
        if not xml_content: return None
        try:
            root = ET.fromstring(xml_content)
            results = {
                'hosts': [],
                'scan_info': {
                    'args': root.get('args'),
                    'start_time': root.get('startstr'),
                    'version': root.get('version')
                }
            }
            
            for host in root.findall('host'):
                status_el = host.find('status')
                host_data: dict[str, Any] = {
                    'status': status_el.get('state') if status_el is not None else 'unknown',
                    'addresses': {},
                    'hostnames': [],
                    'ports': [],
                    'os_matches': []
                }
                
                for addr in host.findall('address'):
                    atyp = addr.get('addrtype')
                    if atyp: host_data['addresses'][atyp] = addr.get('addr')
                
                for hname in host.findall('hostnames/hostname'):
                    host_data['hostnames'].append(hname.get('name'))
                
                ports_el = host.find('ports')
                if ports_el is not None:
                    for port in ports_el.findall('port'):
                        state_el = port.find('state')
                        p_data: dict[str, Any] = {
                            'portid': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': state_el.get('state') if state_el is not None else 'unknown',
                            'service': {},
                            'scripts': []
                        }
                        
                        svc = port.find('service')
                        if svc is not None:
                            p_data['service'] = {
                                'name': svc.get('name'),
                                'product': svc.get('product'),
                                'version': svc.get('version')
                            }
                        
                        for script in port.findall('script'):
                            p_data['scripts'].append({
                                'id': script.get('id'),
                                'output': script.get('output')
                            })
                        host_data['ports'].append(p_data)
                
                os_el = host.find('os')
                if os_el is not None:
                    for os_match in os_el.findall('osmatch'):
                        host_data['os_matches'].append({
                            'name': os_match.get('name'),
                            'accuracy': os_match.get('accuracy')
                        })
                    
                if not isinstance(results.get('hosts'), list):
                    results['hosts'] = []
                results['hosts'].append(host_data)
            return results
        except Exception as e:
            logger.error(f"Nmap parse error: {e}")
            return None

# Example Usage (Simulated)
if __name__ == "__main__":
    scanner = NmapScanner()
    # Mock XML for testing parsing logic without nmap binary
    mock_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun args="nmap -oX - localhost" startstr="Sat Mar 14 00:00:00 2026" version="7.92">
        <host>
            <status state="up" />
            <address addr="127.0.0.1" addrtype="ipv4" />
            <hostnames><hostname name="localhost" type="user"/></hostnames>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open" />
                    <service name="http" product="Apache httpd" version="2.4.41" />
                    <script id="http-title" output="Example Page" />
                </port>
                <port protocol="tcp" portid="8001">
                    <state state="open" />
                    <service name="http" product="Django" version="6.0.3" />
                </port>
            </ports>
            <os><osmatch name="Linux 5.4" accuracy="100" /></os>
        </host>
    </nmaprun>
    """
    parsed = scanner.parse_xml(mock_xml)
    import json
    print(json.dumps(parsed, indent=2))
