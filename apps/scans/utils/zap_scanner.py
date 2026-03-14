import time
import requests
from django.conf import settings

class ZAPScanner:
    """
    Utility class to interact with OWASP ZAP API for web scanning.
    Expects ZAP to be running (e.g. in Docker) and API to be accessible.
    """
    
    def __init__(self):
        self.api_key = settings.ZAP_API_KEY
        self.base_url = settings.ZAP_BASE_URL # e.g. "http://localhost:8080"
        self.owasp_mapping = {
            '1': 'A01:2021-Broken Access Control',
            '2': 'A02:2021-Cryptographic Failures',
            '3': 'A03:2021-Injection',
            '4': 'A04:2021-Insecure Design',
            '5': 'A05:2021-Security Misconfiguration',
            '6': 'A06:2021-Vulnerable and Outdated Components',
            '7': 'A07:2021-Identification and Authentication Failures',
            '8': 'A08:2021-Software and Data Integrity Failures',
            '9': 'A09:2021-Security Logging and Monitoring Failures',
            '10': 'A10:2021-Server-Side Request Forgery'
        }

    def _request(self, path, params=None):
        if params is None: params = {}
        params['apikey'] = self.api_key
        url = f"{self.base_url}/JSON/{path}"
        try:
            response = requests.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            return {'error': str(e)}

    def start_spider(self, target_url):
        return self._request('spider/action/scan/', {'url': target_url})

    def get_spider_status(self, scan_id):
        return self._request('spider/view/status/', {'scanId': scan_id})

    def start_ascan(self, target_url):
        return self._request('ascan/action/scan/', {'url': target_url})

    def get_ascan_status(self, scan_id):
        return self._request('ascan/view/status/', {'scanId': scan_id})

    def get_alerts(self, base_url):
        return self._request('core/view/alerts/', {'baseurl': base_url})

    def get_owasp_category(self, cwe_id):
        """
        Naive mapping from CWE ID to OWASP Top 10 2021.
        In a production environment, this would use a more comprehensive lookup table.
        """
        cwe_to_owasp = {
            '20': 'A03', '79': 'A03', '89': 'A03', # Injection
            '200': 'A01', '284': 'A01',            # Broken Access Control
            '311': 'A02', '312': 'A02',            # Cryptographic Failures
            '16': 'A05', '522': 'A05',             # Security Misconfiguration
            '94': 'A03', '77': 'A03',              # Injection
            '918': 'A10',                          # SSRF
            # Add more mappings as needed
        }
        category_code = cwe_to_owasp.get(str(cwe_id), 'A00') # A00 for unmapped
        # Return full label if code found
        for key, value in self.owasp_mapping.items():
            if value.startswith(category_code):
                return value
        return "Miscellaneous/Uncategorized"

    def run_full_scan(self, target_url, progress_callback=None):
        """
        Orchestrates spider and active scan with error checking and timeouts.
        """
        # 1. Spider
        spider_res = self.start_spider(target_url)
        if 'error' in spider_res: return spider_res
        spider_id = spider_res.get('scan')
        if not spider_id:
            return {'error': 'Failed to start spider: No scan ID returned'}
        
        spider_retries = 0
        max_retries = 1000 # Safety limit
        
        while spider_retries < max_retries:
            status_res = self.get_spider_status(spider_id)
            if 'error' in status_res:
                return status_res
            
            status = status_res.get('status', '0')
            try:
                prog = int(status)
            except (ValueError, TypeError):
                prog = 0
                
            if progress_callback: progress_callback(prog // 2, "Spidering...")
            if prog >= 100: break
            
            spider_retries += 1
            time.sleep(5)

        # 2. Active Scan
        ascan_res = self.start_ascan(target_url)
        if 'error' in ascan_res: return ascan_res
        ascan_id = ascan_res.get('scan')
        if not ascan_id:
            # Active scan might fail if the URL wasn't found in spider
            return {'error': 'Failed to start active scan: No scan ID returned. Ensure target is reachable.'}
        
        ascan_retries = 0
        while ascan_retries < max_retries:
            status_res = self.get_ascan_status(ascan_id)
            if 'error' in status_res:
                return status_res
                
            status = status_res.get('status', '0')
            try:
                prog = int(status)
            except (ValueError, TypeError):
                prog = 0

            if progress_callback: progress_callback(50 + (prog // 2), "Active Scanning...")
            if prog >= 100: break
            
            ascan_retries += 1
            time.sleep(5)

        # 3. Collect Alerts
        alerts_res = self.get_alerts(target_url)
        if 'error' in alerts_res: return alerts_res
        return alerts_res.get('alerts', [])
