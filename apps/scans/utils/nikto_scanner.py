import subprocess
import json
import logging
import os
import tempfile
import csv
import io
from datetime import datetime

logger = logging.getLogger(__name__)

class NiktoScanner:
    def __init__(self, binary_path='nikto'):
        self.binary_path = binary_path

    def _get_base_args(self, target, config=None):
        """
        Builds Nikto command arguments.
        Target should be a URL or IP.
        """
        config = config or {}
        # -h: host, -Format csv: output format, -o -: output to stdout
        args = ['-h', target, '-Format', 'csv', '-o', '-']
        
        # Tuning
        tuning = config.get('tuning')
        if tuning:
            args.extend(['-Tuning', str(tuning)])
            
        # SSL
        if config.get('use_ssl') or target.startswith('https://'):
            args.append('-ssl')
            
        # Timeout
        timeout = config.get('timeout')
        if timeout:
            args.extend(['-timeout', str(timeout)])
            
        # Authentication
        auth = config.get('auth')
        if auth:
            # Format: id:password
            args.extend(['-id', auth])
            
        return args

    def run_scan(self, target, config=None, progress_callback=None):
        """
        Runs Nikto scan and returns parsed JSON data with progress updates.
        """
        command = [self.binary_path]
        command.extend(self._get_base_args(target, config))
        
        logger.info(f"Running Nikto command: {' '.join(command)}")
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            full_output = []
            progress = 10
            
            if process.stdout:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        full_output.append(line)
                        if progress_callback and len(full_output) % 15 == 0:
                            progress = min(98, progress + 2)
                            progress_callback(int(progress), "Nikto: Analyzing target configuration...")

            process.wait(timeout=30)
            stdout = "".join(full_output)
            
            if process.returncode != 0 and not stdout:
                return {
                    'status': 'error',
                    'message': f"Nikto exited with code {process.returncode}",
                    'raw_output': stdout
                }
            
            # Nikto output might contain a banner, so we parse the whole stdout as CSV
            return {
                'status': 'success',
                'raw_data': stdout,
                'parsed_data': self.parse_csv(stdout)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def parse_csv(self, csv_content):
        """Parses Nikto CSV output"""
        try:
            results = {
                'info': {
                    'host': '',
                    'ip': '',
                    'port': '',
                    'banner': '',
                    'nikto_version': ''
                },
                'vulnerabilities': []
            }
            
            reader = csv.reader(io.StringIO(csv_content))
            for row in reader:
                if len(row) < 7:
                    continue
                # Expected Nikto CSV format typically:
                # ["hostname","ip","port","osvdb","method","URI","message"]
                hostname, ip, port, osvdb, method, url, msg = row[:7]
                
                # Assign to info (just take the first valid row's info)
                if not results['info']['host']:
                    results['info']['host'] = hostname
                    results['info']['ip'] = ip
                    results['info']['port'] = port

                # Basic validation
                if hostname.lower() == 'hostname' or ip.lower() == 'ip':
                    continue
                
                vuln = {
                    'id': osvdb,
                    'osvdb': osvdb,
                    'method': method,
                    'url': url,
                    'message': msg,
                    'severity': self._map_severity(msg)
                }
                results['vulnerabilities'].append(vuln)
                
            return results
        except Exception as e:
            logger.error(f"Failed to parse Nikto CSV: {e}")
            return None

    def _map_severity(self, message):
        """Keyword-based severity mapping"""
        if not message: return 'info'
        msg_lower = message.lower()
        if any(word in msg_lower for word in ['critical', 'rce', 'sql injection']): return 'critical'
        if any(word in msg_lower for word in ['high', 'exploit', 'xss']): return 'high'
        if any(word in msg_lower for word in ['medium', 'warning']): return 'medium'
        if any(word in msg_lower for word in ['low', 'header missing']): return 'low'
        return 'info'

# Example Mock Output for testing
if __name__ == "__main__":
    mock_csv = '''"localhost","127.0.0.1","80","0","GET","/login.php","The site appears to be vulnerable to XSS."
"Nikto - v2.1.5/2.1.5"
"localhost","127.0.0.1","80","12345","POST","/admin","Sensitive informational disclosure in headers."'''
    scanner = NiktoScanner()
    parsed = scanner.parse_csv(mock_csv)
    print(json.dumps(parsed, indent=2))
