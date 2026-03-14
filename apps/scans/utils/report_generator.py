import os
from io import BytesIO
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.conf import settings

def generate_pdf_report(template_src, context_dict):
    """
    Renders a Django template into a PDF file using xhtml2pdf.
    """
    template = get_template(template_src)
    html  = template.render(context_dict)
    result = BytesIO()
    
    # Create the PDF
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
    
    if not pdf.err:
        return result.getvalue()
    return None

import csv
from io import StringIO

def generate_csv_report(vulnerabilities):
    """
    Generates a CSV report from a list of vulnerabilities.
    """
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Title', 'Severity', 'Target', 'Component', 'Status', 'CWE ID', 'CVE ID', 'Detected At'])
    
    for v in vulnerabilities:
        writer.writerow([
            v.title, 
            v.get_severity_display(), 
            v.target.name, 
            v.component, 
            v.get_status_display(), 
            v.cwe_id, 
            v.cve_id, 
            v.created_at.strftime('%Y-%m-%d %H:%M')
        ])
        
    return output.getvalue()
