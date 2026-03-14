import requests
import json
import logging
import time
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from ..models import Vulnerability

logger = logging.getLogger(__name__)

class VDBService:
    """Service to interact with external vulnerability databases (NVD, NIST, Exploit-DB)."""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    
    def __init__(self):
        self.api_key = getattr(settings, 'NVD_API_KEY', None)
        self.headers = {}
        if self.api_key:
            self.headers['apiKey'] = self.api_key

    def update_vulnerability(self, vuln_id):
        """Fetches latest data for a specific vulnerability and updates the DB."""
        try:
            vuln = Vulnerability.objects.get(id=vuln_id)
            if not vuln.cve_id:
                return False, "No CVE ID associated with this vulnerability."
            
            # Check if updated recently (within last 24h)
            if vuln.last_updated_db and (timezone.now() - vuln.last_updated_db) < timedelta(hours=24):
                return True, "Already updated today."

            data = self.fetch_nvd_data(vuln.cve_id)
            if not data:
                return False, f"Could not fetch data for {vuln.cve_id}"

            self._process_nvd_data(vuln, data)
            vuln.last_updated_db = timezone.now()
            vuln.save()
            
            return True, "Successfully updated from external databases."
            
        except Vulnerability.DoesNotExist:
            return False, "Vulnerability not found."
        except Exception as e:
            logger.error(f"Error updating vulnerability {vuln_id}: {str(e)}")
            return False, str(e)

    def fetch_nvd_data(self, cve_id):
        """Fetches CVE details from NVD NIST API."""
        try:
            response = requests.get(f"{self.NVD_API_URL}{cve_id}", headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('vulnerabilities'):
                    return data['vulnerabilities'][0]['cve']
            return None
        except Exception as e:
            logger.error(f"NVD API Error: {str(e)}")
            return None

    def _process_nvd_data(self, vuln, cve_data):
        """Parses NVD JSON and updates the model fields."""
        # 1. Update CVSS Scores (prefer V3.1 or V3.0)
        metrics = cve_data.get('metrics', {})
        cvss_data = None
        
        if metrics.get('cvssMetricV31'):
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
        elif metrics.get('cvssMetricV30'):
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
        elif metrics.get('cvssMetricV2'):
            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
            
        if cvss_data:
            vuln.cvss_score = cvss_data.get('baseScore')
            vuln.cvss_vector = cvss_data.get('vectorString', '')
            
            # Map score to severity if not already set or higher
            score = vuln.cvss_score
            if score >= 9.0:
                vuln.severity = 'critical'
            elif score >= 7.0:
                vuln.severity = 'high'
            elif score >= 4.0:
                vuln.severity = 'medium'
            elif score >= 0.1:
                vuln.severity = 'low'

        # 2. Extract CWE
        weaknesses = cve_data.get('weaknesses', [])
        if weaknesses:
            for w in weaknesses:
                desc = w.get('description', [])
                for d in desc:
                    if d.get('value') and 'CWE-' in d['value']:
                        vuln.cwe_id = d['value']
                        break

        # 3. Extract Exploit References
        refs = cve_data.get('references', [])
        exploit_links = []
        for ref in refs:
            tags = ref.get('tags', [])
            if 'Exploit' in tags or 'exploit' in ref.get('url', '').lower():
                exploit_links.append({
                    'url': ref['url'],
                    'source': ref.get('source', 'NVD'),
                    'type': 'exploit'
                })
        
        vuln.exploit_refs = exploit_links
        vuln.has_exploit = len(exploit_links) > 0
        
        # 4. Save raw data for future use
        vuln.external_data = cve_data

    def scheduled_refresh(self):
        """Task to refresh all vulnerabilities with CVE IDs."""
        from django.db.models import Q
        vulns = Vulnerability.objects.exclude(cve_id="").filter(
            Q(last_updated_db__isnull=True) | 
            Q(last_updated_db__lt=timezone.now() - timedelta(days=1))
        )
        
        count = 0
        for vuln in vulns:
            success, _ = self.update_vulnerability(vuln.id)
            if success:
                count += 1
            # Rate limiting compliance for NVD (6 seconds without key, faster with)
            time.sleep(1 if self.api_key else 6)
            
        return count
