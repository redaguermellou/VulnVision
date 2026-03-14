import subprocess
import os
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class GobusterScanner:
    def __init__(self, binary_path='gobuster'):
        self.binary_path = binary_path
        self.wordlists_dir = os.path.join(os.path.dirname(__file__), 'wordlists')

    def _get_wordlist_path(self, wordlist_name):
        """Returns the absolute path to a built-in wordlist"""
        if not wordlist_name.endswith('.txt'):
            wordlist_name += '.txt'
        
        path = os.path.join(self.wordlists_dir, wordlist_name)
        if os.path.exists(path):
            return path
        return os.path.join(self.wordlists_dir, 'common.txt') # Fallback

    def run_scan(self, target_url, config=None, progress_callback=None):
        """
        Runs gobuster dir scan and returns findings with real-time progress.
        """
        config = config or {}
        wordlist_name = config.get('wordlist', 'common.txt')
        wordlist_path = self._get_wordlist_path(wordlist_name)
        
        # Build command: gobuster dir -u <url> -w <wordlist>
        command = [self.binary_path, 'dir', '-u', target_url, '-w', wordlist_path, '--no-error']
        
        # Threading
        threads = config.get('threads', 10)
        command.extend(['-t', str(threads)])
        
        # Extensions
        extensions = config.get('extensions')
        if extensions:
            command.extend(['-x', extensions])
            
        # Status filters
        status_codes = config.get('status_codes', '200,204,301,302,307,401,403')
        command.extend(['-s', status_codes])
        
        logger.info(f"Running Gobuster: {' '.join(command)}")
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            full_output = []
            findings = []
            
            # Pattern to match: "Progress: 123 / 1000 (12.30%)"
            progress_pattern = re.compile(r'Progress:\s+\d+\s+\/\s+\d+\s+\(([\d\.]+)%\)')
            finding_pattern = re.compile(r'(\/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]')
            
            if process.stdout:
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        full_output.append(line)
                        
                        # Parse progress
                        prog_match = progress_pattern.search(line)
                        if prog_match and progress_callback:
                            try:
                                progress = float(prog_match.group(1))
                                progress_callback(int(progress), "Gobuster: Searching paths...")
                            except ValueError:
                                pass

                        # Parse findings on the fly
                        match = finding_pattern.search(line)
                        if match:
                            findings.append({
                                'path': match.group(1),
                                'status': match.group(2),
                                'size': match.group(3),
                                'severity': self._determine_severity(match.group(1), match.group(2))
                            })

            process.wait(timeout=30)
            stdout = "".join(full_output)
            
            if process.returncode != 0 and not findings:
                return {
                    'status': 'error',
                    'message': f"Gobuster exited with code {process.returncode}",
                    'raw_output': stdout
                }
                
            return {
                'status': 'success',
                'raw_output': stdout,
                'parsed_data': findings
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def parse_output(self, output):
        """Fallback parser if streaming fails"""
        findings = []
        pattern = re.compile(r'(\/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]')
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                findings.append({
                    'path': match.group(1),
                    'status': match.group(2),
                    'size': match.group(3),
                    'severity': self._determine_severity(match.group(1), match.group(2))
                })
        return findings

    def _determine_severity(self, path, status):
        """Roughly determine severity based on file type/path"""
        path_lower = path.lower()
        if any(x in path_lower for x in ['.env', '.git', 'config.php.bak', 'database.sql']):
            return 'critical'
        if status == '200' and any(x in path_lower for x in ['admin', 'panel', 'dashboard', 'phpmyadmin']):
            return 'high'
        if any(x in path_lower for x in ['login', 'account', 'secret', 'private']):
            return 'medium'
        return 'low'

    def parse_output(self, output):
        """
        Parses Gobuster text output.
        Line format usually: /path (Status: 200) [Size: 123]
        """
        findings = []
        # Regex to match: /admin (Status: 200) [Size: 1234]
        pattern = re.compile(r'(\/[^\s]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]')
        
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                path = match.group(1)
                status = match.group(2)
                size = match.group(3)
                
                finding = {
                    'path': path,
                    'status': status,
                    'size': size,
                    'severity': self._determine_severity(path, status)
                }
                findings.append(finding)
                
        return findings

    def _determine_severity(self, path, status):
        """Roughly determine severity based on file type/path"""
        path_lower = path.lower()
        
        # Critical: backup of config, env files, .git
        if any(x in path_lower for x in ['.env', '.git', 'config.php.bak', 'database.sql']):
            return 'critical'
            
        # High: Admin panels accessible (200)
        if status == '200' and any(x in path_lower for x in ['admin', 'panel', 'dashboard', 'phpmyadmin']):
            return 'high'
            
        # Medium: Login pages, account portals
        if any(x in path_lower for x in ['login', 'account', 'secret', 'private']):
            return 'medium'
            
        # Low: Normal directories found (301, 200)
        return 'low'

# Mock Output for testing
if __name__ == "__main__":
    scanner = GobusterScanner()
    mock_out = """
/admin                (Status: 200) [Size: 1245]
/login                (Status: 200) [Size: 856]
/config.php.bak       (Status: 200) [Size: 45]
/.env                 (Status: 403) [Size: 22]
/images               (Status: 301) [Size: 0]
    """
    import json
    print(json.dumps(scanner.parse_output(mock_out), indent=2))
