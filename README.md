# VulnVision

Advanced Web Vulnerability Management and Reporting Dashboard.

## Features
- **Network Scanning**: Integrated Nmap for port and service discovery.
- **Web Vulnerability Scanning**: Nikto and OWASP ZAP integration.
- **OWASP Top 10 Automation**: Deep mapping of findings to OWASP risk categories.
- **Analytics & Trends**: Longitudinal tracking of security posture and remediation progress.
- **Professional Reporting**: PDF and CSV export for executive and technical stakeholders.
- **Task Automation**: Asynchronous scanning using Celery and Redis.

## Technology Stack
- **Backend**: Django (Python)
- **Frontend**: Bootstrap 5, Chart.js
- **Broker/Task Queue**: Redis, Celery
- **Security Tools**: Nmap, Nikto, Gobuster, OWASP ZAP

## Getting Started
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`.
3. Set up environment variables in `.env`.
4. Run migrations: `python manage.py migrate`.
5. Start Celery worker: `celery -A vulnvision worker --loglevel=info`.
6. Run the server: `python manage.py runserver`.
