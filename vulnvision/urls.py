from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.db import connection
import time

_start_time = time.time()

def health_check(request):
    """Lightweight health check for Docker / load balancers."""
    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    return JsonResponse({
        'status': 'ok' if db_ok else 'degraded',
        'database': 'ok' if db_ok else 'error',
        'uptime_seconds': round(time.time() - _start_time),
    }, status=200 if db_ok else 503)

urlpatterns = [
    path('health/', health_check, name='health_check'),
    path('admin/', admin.site.urls),
    path('', include('apps.core.urls')),
    path('targets/', include('apps.targets.urls')),
    path('scans/', include('apps.scans.urls')),
    path('ai/', include('apps.ai_assistant.urls')),
    path('api/v1/', include('apps.api.urls', namespace='api')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
