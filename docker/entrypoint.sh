#!/bin/sh
# ════════════════════════════════════════════════════════════
# VulnVision – Docker entrypoint
# Runs migrations, then executes CMD (gunicorn / celery / etc.)
# ════════════════════════════════════════════════════════════
set -e

echo "🔍 VulnVision entrypoint starting..."

# ── Wait for PostgreSQL ──────────────────────────────────────
wait_for_db() {
    echo "⏳ Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}..."
    until python -c "
import psycopg2, os, sys
try:
    psycopg2.connect(
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        host=os.environ['DB_HOST'],
        port=os.environ.get('DB_PORT', 5432),
        connect_timeout=3,
    )
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; do
        echo "  → Not ready yet, retrying in 2s..."
        sleep 2
    done
    echo "✅ PostgreSQL is ready."
}

# ── Wait for Redis ───────────────────────────────────────────
wait_for_redis() {
    echo "⏳ Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."
    until redis-cli -h "${REDIS_HOST:-redis}" -p "${REDIS_PORT:-6379}" \
          -a "${REDIS_PASSWORD}" --no-auth-warning ping 2>/dev/null | grep -q PONG; do
        echo "  → Not ready yet, retrying in 2s..."
        sleep 2
    done
    echo "✅ Redis is ready."
}

# ── Django setup (only for web / beat, not needed for workers starting later)
run_django_setup() {
    echo "🗄️  Running database migrations..."
    python manage.py migrate --noinput

    echo "📋 Creating default superuser (if not exists)..."
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser(
        email='${DJANGO_SUPERUSER_EMAIL:-admin@vulnvision.local}',
        password='${DJANGO_SUPERUSER_PASSWORD:-Admin@12345}',
    )
    print('Superuser created.')
else:
    print('Superuser already exists.')
" 2>/dev/null || true

    echo "📦 Collecting static files..."
    python manage.py collectstatic --noinput --clear 2>/dev/null || true
}

# Only run Django setup for web and beat containers
case "$1" in
    gunicorn|manage.py)
        wait_for_db
        wait_for_redis
        run_django_setup
        ;;
    celery)
        case "$2" in
            beat)
                wait_for_db
                wait_for_redis
                run_django_setup
                ;;
            worker|flower)
                wait_for_db
                wait_for_redis
                ;;
        esac
        ;;
esac

echo "🚀 Starting: $*"
exec "$@"
