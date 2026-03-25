# VulnVision — Admin Guide

> This guide is intended for system administrators responsible for managing VulnVision users, configuring the platform, maintaining backups, and tuning performance.

---

## Table of Contents

1. [User Management](#1-user-management)
2. [System Configuration](#2-system-configuration)
3. [Backup & Restore](#3-backup--restore)
4. [Performance Tuning](#4-performance-tuning)

---

## 1. User Management

### 1.1 Roles

| Role | Capabilities |
|---|---|
| **Viewer** | Read-only: view targets, scans, and vulnerabilities. 10 AI queries/day, 500 API calls/day |
| **Analyst** | Full scanning access: create/run scans, generate reports. 20 AI queries/day, 2000 API calls/day |
| **Admin** | All capabilities + user management, system config. Unlimited API/AI |

### 1.2 Creating Users via Admin Panel

1. Log in as a superuser and go to `/admin/`.
2. Navigate to **Core → Users → + Add User**.
3. Set email, password, and **Role**.
4. Optionally set **Company** and **Full Name**.
5. Click **Save**.

### 1.3 Creating Users via Management Command

```bash
# Create a regular Analyst user
docker compose exec web python manage.py shell -c "
from apps.core.models import User
User.objects.create_user(
    email='analyst@example.com',
    password='SecurePass123!',
    full_name='Jane Doe',
    role='analyst',
)
print('Created.')
"

# Promote an existing user to admin
docker compose exec web python manage.py shell -c "
from apps.core.models import User
u = User.objects.get(email='analyst@example.com')
u.role = 'admin'
u.is_staff = True
u.save()
"
```

### 1.4 API Key Management

Every user gets an API key auto-generated on account creation (UUID v4). To **rotate** a key:

```bash
# Via Django shell
docker compose exec web python manage.py shell -c "
import uuid
from apps.core.models import User
u = User.objects.get(email='analyst@example.com')
u.api_key = str(uuid.uuid4())
u.save()
print('New key:', u.api_key)
"
```

Or via the REST API (admin only):
```bash
curl -X PATCH https://your-domain.com/api/v1/auth/me/ \
     -H "Authorization: Token ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"api_key": "new-uuid-here"}'
```

### 1.5 Deactivating Users

Set `is_active = False` — the user cannot log in but their data is preserved:

```bash
python manage.py shell -c "
from apps.core.models import User
User.objects.filter(email='leavinguser@example.com').update(is_active=False)
"
```

### 1.6 Custom Rate Limit Overrides

To override throttle limits for a single user, add a `rate_limit_override` field by extending the model, or simply adjust `ROLE_THROTTLE_RATES` in `settings.py` for whole-role overrides:

```python
# settings.py
ROLE_THROTTLE_RATES = {
    'ai_query.analyst': '50/day',  # Bump analyst AI limit to 50
    'scan_create.viewer': '5/hour', # Allow viewers to create 5 scans/h
}
```

---

## 2. System Configuration

### 2.1 Environment Variables Reference

All configuration is done via `.env` (or environment variables in Docker Compose).

#### Django

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | **Required** | 50+ character random string |
| `DEBUG` | `False` | Never `True` in production |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames |
| `TIME_ZONE` | `Africa/Casablanca` | Django timezone |

#### Database

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | *(unset = SQLite)* | Set to `postgres` in Docker |
| `DB_NAME` | `vulnvision` | Database name |
| `DB_USER` | `vulnvision` | Database user |
| `DB_PASSWORD` | **Required** | Strong password |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_SSL_MODE` | `prefer` | `require` in strict prod |

#### Redis & Celery

| Variable | Description |
|---|---|
| `REDIS_PASSWORD` | Redis auth password |
| `CELERY_BROKER_URL` | `redis://:PASSWORD@redis:6379/0` |
| `CELERY_RESULT_BACKEND` | `redis://:PASSWORD@redis:6379/1` |

#### Email

| Variable | Description |
|---|---|
| `EMAIL_HOST` | SMTP server (e.g. `smtp.gmail.com`) |
| `EMAIL_PORT` | Usually `587` (TLS) |
| `EMAIL_USE_TLS` | `True` |
| `EMAIL_HOST_USER` | SMTP username |
| `EMAIL_HOST_PASSWORD` | SMTP password / app password |

#### AI & External APIs

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google Gemini API key |
| `GEMMA_MODEL_NAME` | Model to use (default: `gemma-3-27b-it`) |
| `NVD_API_KEY` | NVD rate-limit key (optional, free) |
| `ZAP_API_KEY` | OWASP ZAP API key |
| `ZAP_BASE_URL` | ZAP daemon URL |

### 2.2 Django Admin Panel

Access the built-in admin at `/admin/` with your superuser credentials.

Key sections:

| Section | Purpose |
|---|---|
| **Core → Users** | Manage user accounts, roles, API keys |
| **Scans → Scans** | View/delete scan records |
| **Scans → Vulnerabilities** | Bulk-update vulnerability statuses |
| **AI Assistant → Remediation Guides** | Clear stale cached guides |
| **Auth Token → Tokens** | Revoke DRF auth tokens |
| **Celery Beat → Periodic Tasks** | Manage scheduled tasks |

### 2.3 Celery Beat Scheduled Tasks

Default schedule (configured in `settings.py`):

| Task | Schedule | Description |
|---|---|---|
| `daily_vulnerability_db_refresh` | Daily 02:00 | Refresh NVD/CVE data for all vulns |
| `send_weekly_reports_task` | Monday 08:00 | Email security digest to all users |

To modify via Django Admin:
1. Go to `/admin/django_celery_beat/periodictask/`.
2. Click the task name and change the `Interval` or `Crontab` schedule.

### 2.4 Nginx TLS Configuration

For production, replace the self-signed certificate with Let's Encrypt:

```bash
# On the host (not inside Docker)
apt install certbot

certbot certonly --standalone \
  -d your-domain.com \
  --email admin@your-domain.com \
  --agree-tos --non-interactive

# Copy certs to Docker volume
docker cp /etc/letsencrypt/live/your-domain.com/fullchain.pem \
    vulnvision_nginx:/etc/nginx/certs/
docker cp /etc/letsencrypt/live/your-domain.com/privkey.pem \
    vulnvision_nginx:/etc/nginx/certs/

# Reload nginx
docker compose exec nginx nginx -s reload
```

Set up auto-renewal:
```bash
# /etc/cron.d/certbot-renew
0 3 * * * root certbot renew --quiet --post-hook "docker compose -f /opt/vulnvision/docker-compose.yml exec nginx nginx -s reload"
```

---

## 3. Backup & Restore

### 3.1 Database Backup

```bash
# Manual backup
docker compose exec postgres pg_dump \
    -U vulnvision vulnvision \
    | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Automated daily backup (add to crontab)
0 1 * * * docker compose -f /opt/vulnvision/docker-compose.yml exec -T postgres \
    pg_dump -U vulnvision vulnvision \
    | gzip > /backups/vulnvision_$(date +\%Y\%m\%d).sql.gz
```

### 3.2 Database Restore

```bash
# Stop the web service first
docker compose stop web celery_worker celery_beat

# Restore
gunzip -c backup_20260314.sql.gz \
    | docker compose exec -T postgres psql -U vulnvision vulnvision

# Restart services
docker compose start web celery_worker celery_beat
```

### 3.3 Media Files Backup

User-uploaded media (profile images, report attachments):

```bash
# Backup
docker compose run --rm web tar czf - /app/media > media_backup_$(date +%Y%m%d).tar.gz

# Restore
docker compose run --rm -i web tar xzf - -C / < media_backup_20260314.tar.gz
```

### 3.4 Full Stack Backup Script

Save as `/opt/vulnvision/backup.sh`:

```bash
#!/bin/bash
set -e
BACKUP_DIR="/backups/vulnvision"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

echo "Backing up database..."
docker compose exec -T postgres pg_dump -U vulnvision vulnvision \
    | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

echo "Backing up media..."
docker compose run --rm web tar czf - /app/media \
    > "$BACKUP_DIR/media_$DATE.tar.gz"

echo "Backing up .env..."
cp /opt/vulnvision/.env "$BACKUP_DIR/env_$DATE.bak"

# Keep only 30 days
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
echo "Backup complete: $BACKUP_DIR"
```

```bash
chmod +x /opt/vulnvision/backup.sh
# Add to cron: daily at 01:30
30 1 * * * /opt/vulnvision/backup.sh >> /var/log/vulnvision-backup.log 2>&1
```

---

## 4. Performance Tuning

### 4.1 Gunicorn Workers

Edit the CMD in `Dockerfile` or override in `docker-compose.yml`:

```yaml
# docker-compose.yml
services:
  web:
    command:
      - gunicorn
      - vulnvision.wsgi:application
      - --bind=0.0.0.0:8000
      - --workers=8          # Recommended: 2×CPU + 1
      - --worker-class=gthread
      - --threads=4
      - --timeout=120
```

**Rule of thumb:** `workers = (2 × CPU_cores) + 1`

### 4.2 Celery Concurrency

```yaml
# docker-compose.yml
celery_worker:
  command:
    - celery
    - -A
    - vulnvision
    - worker
    - --concurrency=8        # Match CPU count for CPU-bound scans
    - --queues=default,scans,reports
```

For I/O-heavy tasks (network scans), use more workers than CPUs:
```bash
--concurrency=16 --pool=gevent
```

### 4.3 PostgreSQL Tuning

Edit `docker-compose.yml` postgres command:

```yaml
postgres:
  command:
    - postgres
    - -c max_connections=200
    - -c shared_buffers=256MB      # ~25% of RAM
    - -c effective_cache_size=1GB  # ~75% of RAM
    - -c work_mem=4MB
    - -c wal_buffers=16MB
    - -c checkpoint_completion_target=0.9
```

### 4.4 Redis Memory

```yaml
redis:
  command: >
    redis-server
    --requirepass ${REDIS_PASSWORD}
    --maxmemory 512mb          # Increase for larger deployments
    --maxmemory-policy allkeys-lru
```

### 4.5 Django Database Connection Pooling

`CONN_MAX_AGE` is already set to `60` seconds in `settings.py`. For heavy traffic, add PgBouncer:

```yaml
# Add to docker-compose.yml
pgbouncer:
  image: bitnami/pgbouncer:1.22
  environment:
    POSTGRESQL_HOST: postgres
    POSTGRESQL_USERNAME: vulnvision
    POSTGRESQL_PASSWORD: ${DB_PASSWORD}
    POSTGRESQL_DATABASE: vulnvision
    PGBOUNCER_POOL_MODE: transaction
    PGBOUNCER_MAX_CLIENT_CONN: 500
  networks:
    - vulnvision_net
```

Then set `DB_HOST=pgbouncer` in `.env`.

### 4.6 Monitoring

Monitor all services via **Flower** at `/flower/` (internal network only):

```
http://localhost:5555  →  Celery task queue, worker status, task rates
```

For production monitoring, integrate with:
- **Prometheus** + **Grafana** — metrics dashboards
- **Sentry** — error tracking
- **Uptime Kuma** — endpoint health monitoring

### 4.7 Log Management

All logs are written to the `app_logs` Docker volume (`/app/logs/`):

| File | Contents |
|---|---|
| `gunicorn-access.log` | HTTP request log |
| `gunicorn-error.log` | Application errors |
| `celery-worker.log` | Task execution log |
| `celery-beat.log` | Scheduler log |

To tail logs in real-time:
```bash
docker compose logs -f web
docker compose logs -f celery_worker
tail -f $(docker volume inspect vulnvision_app_logs --format '{{.Mountpoint}}')/gunicorn-error.log
```

---

*Next: [Developer Guide](developer_guide.md)*
