import json
import logging
import requests
import markdown
from django.conf import settings
from ..models import RemediationGuide

logger = logging.getLogger(__name__)

class RemediationService:
    def __init__(self):
        self.api_key = getattr(settings, 'GEMINI_API_KEY', None)
        self.model_name = getattr(settings, 'GEMMA_MODEL_NAME', 'gemini-1.5-flash')
        
        # Override to support standard endpoint
        if 'gemma' in self.model_name.lower():
            self.model_name = 'gemini-1.5-flash'

    def generate_guide(self, obj):
        """Generates a detailed remediation guide for a vulnerability or OWASP alert."""
        if not self.api_key:
            return None

        is_owasp = hasattr(obj, 'alert')
        title = obj.alert if is_owasp else obj.title
        description = obj.description
        severity = obj.risk if is_owasp else obj.severity
        cve = "" if is_owasp else (obj.cve_id or "")
        cwe = obj.cweid if is_owasp else (obj.cwe_id or "")
        component = obj.url if is_owasp else (obj.component or "")

        prompt = f"""
        You are a senior security engineer. Generate a DETAILED remediation guide for the following security finding:
        
        Type: {"OWASP Alert" if is_owasp else "Vulnerability"}
        Title: {title}
        Description: {description}
        Severity: {severity}
        CVE: {cve or 'N/A'}
        CWE: {cwe or 'N/A'}
        Affected Component/URL: {component or 'N/A'}

        Return ONLY a JSON object with the following structure:
        {{
            "problem_description": "Detailed explanation of the vulnerability",
            "impact_analysis": "Security impact of this vulnerability",
            "step_by_step_fix": ["step 1", "step 2", ...],
            "code_snippets": [
                {{ "language": "php", "code": "...", "description": "Fix in PHP" }},
                {{ "language": "python", "code": "...", "description": "Fix in Python" }},
                {{ "language": "javascript", "code": "...", "description": "Fix in JavaScript" }}
            ],
            "server_configuration": [
                {{ "server": "nginx", "config": "..." }},
                {{ "server": "apache", "config": "..." }}
            ],
            "verification_steps": ["how to check if fixed 1", "2"],
            "prevention_tips": ["how to avoid in future 1", "2"],
            "documentation_links": [
                {{ "title": "OWASP Guide", "url": "..." }},
                {{ "title": "CWE Detail", "url": "..." }}
            ]
        }}
        """

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        try:
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'}, timeout=10)
            if response.status_code != 200:
                return None
                
            text = response.json()['candidates'][0]['content']['parts'][0]['text'].strip()
            
            # Clean JSON response from potential markdown wrapping
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].strip()
            
            guide_data = json.loads(text)
            
            # Generate HTML rendering
            html_content = self.render_to_html(guide_data)
            
            # Save or update guide in DB
            filter_kwargs = {'owasp_alert': obj} if is_owasp else {'vulnerability': obj}
            guide, created = RemediationGuide.objects.get_or_create(
                **filter_kwargs,
                defaults={'content': guide_data, 'html_content': html_content}
            )
            
            if not created:
                guide.content = guide_data
                guide.html_content = html_content
                guide.version += 1
                guide.save()
                
            return guide
        except Exception as e:
            logger.error(f"Error generating remediation guide: {str(e)}")
            return None

    def render_to_html(self, data):
        """Converts structured guide data to a clean HTML format."""
        md_lines = []
        md_lines.append(f"## Problem Description\n{data['problem_description']}")
        md_lines.append(f"## Impact Analysis\n{data['impact_analysis']}")
        
        md_lines.append("## Step-by-Step Remediation")
        for i, step in enumerate(data['step_by_step_fix'], 1):
            md_lines.append(f"{i}. {step}")
            
        md_lines.append("## Code Snippets")
        for snippet in data['code_snippets']:
            md_lines.append(f"### {snippet['description']}")
            md_lines.append(f"```{snippet['language']}\n{snippet['code']}\n```")
            
        if data.get('server_configuration'):
            md_lines.append("## Server Configuration")
            for conf in data['server_configuration']:
                md_lines.append(f"### {conf['server'].upper()}")
                md_lines.append(f"```nginx\n{conf['config']}\n```")
                
        md_lines.append("## Verification Steps")
        for step in data['verification_steps']:
            md_lines.append(f"- {step}")
            
        md_lines.append("## Prevention Tips")
        for tip in data['prevention_tips']:
            md_lines.append(f"- {tip}")
            
        md_lines.append("## References")
        for link in data['documentation_links']:
            md_lines.append(f"- [{link['title']}]({link['url']})")
            
        return markdown.markdown("\n\n".join(md_lines), extensions=['fenced_code', 'codehilite'])
