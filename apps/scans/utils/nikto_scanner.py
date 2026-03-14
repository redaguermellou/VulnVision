import subprocess
import json
import logging
import os
import tempfile
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
        # -h: host, -Format json: output format, -o -: output to stdout
        args = ['-h', target, '-Format', 'json', '-o', '-']
        
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
            
            json_start = stdout.find('{')
            if json_start != -1:
                json_data = stdout[json_start:]
                return {
                    'status': 'success',
                    'raw_data': stdout,
                    'parsed_data': self.parse_json(json_data)
                }
            else:
                return {
                    'status': 'error',
                    'message': "Could not find JSON output in Nikto results.",
                    'raw_output': stdout
                }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def parse_json(self, json_content):
        """Parses Nikto JSON output"""
        try:
            data = json.loads(json_content)
            results = {
                'info': {
                    'host': data.get('host'),
                    'ip': data.get('ip'),
                    'port': data.get('port'),
                    'banner': data.get('banner'),
                    'nikto_version': data.get('version')
                },
                'vulnerabilities': []
            }
            
            for item in data.get('vulnerabilities', []):
                vuln = {
                    'id': item.get('id'),
                    'osvdb': item.get('osvdb'),
                    'method': item.get('method'),
                    'url': item.get('url'),
                    'message': item.get('msg'),
                    'severity': self._map_severity(item.get('msg', ''))
                }
                results['vulnerabilities'].append(vuln)
                
            return results
        except Exception as e:
            logger.error(f"Failed to parse Nikto JSON: {e}")
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
    mock_json = """
    {
        "host": "localhost",
        "ip": "127.0.0.1",
        "port": "80",
        "banner": "Apache/2.4.41 (Ubuntu)",
        "version": "2.1.6",
        "vulnerabilities": [
            {
                "id": "1",
                "osvdb": "0",
                "method": "GET",
                "url": "/login.php",
                "msg": "The site appears to be vulnerable to XSS."
            },
            {
                "id": "2",
                "osvdb": "12345",
                "method": "POST",
                "url": "/admin",
                "msg": "Sensitive informational disclosure in headers."
            }
        ]
    }
    """
    scanner = NiktoScanner()
    parsed = scanner.parse_json(mock_json)
    print(json.dumps(parsed, indent=2))
