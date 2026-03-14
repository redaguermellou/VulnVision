import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
SECRET_KEY = os.getenv('SECRET_KEY', 'default-insecure-key-for-dev')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')

ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'crispy_forms',
    'crispy_bootstrap5',
    'django_extensions',
    'rest_framework',
    'rest_framework.authtoken',
    'drf_spectacular',

    # Local apps
    'apps.core',
    'apps.targets',
    'apps.scans',
    'apps.ai_assistant',
    'apps.api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vulnvision.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'], # Added custom templates folder path
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnvision.wsgi.application'

# ── Database ─────────────────────────────────────────────────
# Uses PostgreSQL when DB_HOST is set (Docker/production),
# falls back to SQLite for local dev.
if os.getenv('DB_HOST'):
    DATABASES = {
        'default': {
            'ENGINE':   'django.db.backends.postgresql',
            'NAME':     os.getenv('DB_NAME', 'vulnvision'),
            'USER':     os.getenv('DB_USER', 'vulnvision'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST':     os.getenv('DB_HOST', 'postgres'),
            'PORT':     os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': 60,
            'OPTIONS': {
                'sslmode': os.getenv('DB_SSL_MODE', 'prefer'),
            },
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Casablanca'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User Model definition
AUTH_USER_MODEL = 'core.User'

# ── ALLOWED_HOSTS (env configurable) ─────────────────────────
_hosts = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in _hosts.split(',') if h.strip()]
CSRF_TRUSTED_ORIGINS = [
    f"https://{h}" for h in ALLOWED_HOSTS if h not in ('localhost', '127.0.0.1')
] + ['http://localhost', 'http://127.0.0.1']

# ── Cache (Redis in Docker, local-memory fallback) ────────────
if os.getenv('REDIS_HOST') or os.getenv('CACHE_LOCATION'):
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': os.getenv(
                'CACHE_LOCATION',
                f"redis://:{os.getenv('REDIS_PASSWORD', '')}@"
                f"{os.getenv('REDIS_HOST', 'redis')}:"
                f"{os.getenv('REDIS_PORT', '6379')}/2"
            ),
            'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient'},
            'KEY_PREFIX': 'vulnvision',
            'TIMEOUT': 300,
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    }

# Crispy Forms specific Configs
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5"

# Setup basic Authentication Redirection
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'home'
LOGOUT_REDIRECT_URL = 'login'

# Email Configuration
if os.getenv('PRODUCTION', 'False').lower() in ('true', '1', 't'):
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.getenv('EMAIL_HOST')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
    EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'VulnVision <noreply@vulnvision.com>')
else:
    # Console for Development
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Messages framework mapping for Bootstrap 5
from django.contrib.messages import constants as messages
MESSAGE_TAGS = {
    messages.DEBUG: 'secondary',
    messages.INFO: 'info',
    messages.SUCCESS: 'success',
    messages.WARNING: 'warning',
    messages.ERROR: 'danger',
}

# Celery Configuration
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# OWASP ZAP API Configuration
ZAP_API_KEY = os.getenv('ZAP_API_KEY', 'vulnvision_zap_key')
ZAP_BASE_URL = os.getenv('ZAP_BASE_URL', 'http://localhost:8080')
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60 # 30 minutes

# AI Configuration
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMMA_MODEL_NAME = os.getenv('GEMMA_MODEL_NAME', 'gemma-3-27b-it')

# External Vulnerability Database Integration
NVD_API_KEY = os.getenv('NVD_API_KEY', '')  # Optional: increases NVD API rate limit

# ─────────────────────────────────────────────
# Django REST Framework Configuration
# ─────────────────────────────────────────────
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'apps.api.authentication.APIKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.api.pagination.StandardResultsPagination',
    'PAGE_SIZE': 25,
    'DEFAULT_FILTER_BACKENDS': [
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    # ── Global throttle defaults (overridden per-view as needed) ──────────
    'DEFAULT_THROTTLE_CLASSES': [
        'apps.api.throttles.AnonBurstThrottle',
        'apps.api.throttles.UserSustainedThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        # Built-in DRF named scopes (fallback)
        'anon':            '30/min',
        'user':            '1000/day',
        # Custom scopes used by VulnVision throttle classes
        'user_sustained':  '1000/day',
        'scan_create':     '5/hour',
        'ai_query':        '20/day',
        'export':          '3/hour',
    },
}

# ── Per-role throttle overrides (format: "scope.role": "N/period") ────────
# These override the class-level defaults inside RoleAwareRateThrottle.
# Modify here without touching code to tune limits per environment/plan.
ROLE_THROTTLE_RATES = {
    # Viewer (read-only, restricted)
    'user_sustained.viewer':  '500/day',
    'scan_create.viewer':     '3/hour',
    'ai_query.viewer':        '10/day',
    'export.viewer':          '1/hour',
    # Analyst (default power user)
    'user_sustained.analyst': '2000/day',
    'scan_create.analyst':    '5/hour',
    'ai_query.analyst':       '20/day',
    'export.analyst':         '3/hour',
    # Admin — use None (unlimited) handled inside RoleAwareRateThrottle
    'user_sustained.admin':   None,
    'scan_create.admin':      None,
    'ai_query.admin':         None,
    'export.admin':           None,
}


# ─────────────────────────────────────────────
# drf-spectacular (OpenAPI) Configuration
# ─────────────────────────────────────────────
SPECTACULAR_SETTINGS = {
    'TITLE': 'VulnVision REST API',
    'DESCRIPTION': (
        'Comprehensive API for the VulnVision security scanning platform. '
        'Manage targets, scans, and vulnerability findings. '
        'Supports Token, Session, and API Key authentication.'
    ),
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'CONTACT': {'name': 'VulnVision Team'},
    'LICENSE': {'name': 'MIT'},
    'TAGS': [
        {'name': 'auth',            'description': 'Authentication & current user'},
        {'name': 'targets',         'description': 'Target management'},
        {'name': 'scans',           'description': 'Scan management & control'},
        {'name': 'vulnerabilities', 'description': 'Vulnerability findings'},
        {'name': 'owasp-scans',     'description': 'OWASP ZAP scan results'},
        {'name': 'dashboard',       'description': 'Aggregated stats'},
    ],
    'SECURITY': [
        {'tokenAuth': []},
        {'apiKeyAuth': []},
    ],
    'COMPONENT_SPLIT_REQUEST': True,
}

# External Vulnerability Database Integration
NVD_API_KEY = os.getenv('NVD_API_KEY', '')  # Optional

# Celery Beat Scheduled Tasks
from celery.schedules import crontab
CELERY_BEAT_SCHEDULE = {
    'daily-vuln-db-refresh': {
        'task': 'apps.scans.tasks.daily_vulnerability_db_refresh',
        'schedule': crontab(hour=2, minute=0),  # Every day at 2:00 AM
    },
    'weekly-security-reports': {
        'task': 'apps.scans.tasks.send_weekly_reports_task',
        'schedule': crontab(hour=8, minute=0, day_of_week='monday'),  # Every Monday 8 AM
    },
}

