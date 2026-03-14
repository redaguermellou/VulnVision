"""
VulnVision API Rate Limiting / Throttle Classes
================================================
Hierarchy:
  1. RoleAwareRateThrottle  – base class, reads limits from DB or settings
  2. ScanCreateThrottle     – max 5 scans/hour  (admin: unlimited)
  3. AIQueryThrottle        – max 20 AI calls/day (admin: 200)
  4. ExportThrottle         – max 3 exports/hour  (admin: unlimited)
  5. AnonBurstThrottle      – 30 req/min for unauthenticated users
  6. UserSustainedThrottle  – 1000 req/day for authenticated users

Response headers (X-RateLimit-*) are injected via RateLimitHeaderMixin.
"""
import time
from rest_framework.throttling import (
    AnonRateThrottle,
    UserRateThrottle,
    ScopedRateThrottle,
)
from django.core.cache import cache


# ─────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────

def _parse_rate(rate_str):
    """'20/day' → (20, 86400).  Returns (None, None) on failure."""
    if not rate_str:
        return None, None
    try:
        num, period = rate_str.split('/')
        period_map = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400,
                      'sec': 1, 'min': 60, 'hour': 3600, 'day': 86400}
        return int(num), period_map[period.lower()]
    except (ValueError, KeyError):
        return None, None


# ─────────────────────────────────────────────────────
# Base: role-aware throttle
# ─────────────────────────────────────────────────────

class RoleAwareRateThrottle(UserRateThrottle):
    """
    Reads per-role limits from settings.ROLE_THROTTLE_RATES.
    Falls back to the class-level ``rate`` if no role-specific rate is found.
    Admins (is_staff=True) are never throttled.
    """
    scope = 'user'
    # Subclasses set these
    anon_rate    = '60/hour'
    viewer_rate  = '100/hour'
    analyst_rate = '500/hour'
    admin_rate   = None          # No limit

    def get_rate(self):
        from django.conf import settings
        user = getattr(self, 'request', None) and self.request.user

        if user and user.is_authenticated:
            # Staff → unlimited
            if user.is_staff:
                return None
            # Check DB-level override first
            override = getattr(user, 'rate_limit_override', None)
            if override:
                return override
            # Role mapping
            role = getattr(user, 'role', 'viewer')
            role_map = {
                'admin':   self.admin_rate,
                'analyst': self.analyst_rate,
                'viewer':  self.viewer_rate,
            }
            rate = role_map.get(role, self.viewer_rate)
            # Also check settings overrides
            settings_map = getattr(settings, 'ROLE_THROTTLE_RATES', {})
            scope_key = f"{self.scope}.{role}"
            return settings_map.get(scope_key, rate)

        return self.anon_rate

    def allow_request(self, request, view):
        self.request = request
        self.rate = self.get_rate()
        if self.rate is None:
            self.num_requests, self.duration = None, None
            return True  # Staff bypass
        self.num_requests, self.duration = _parse_rate(self.rate)
        if self.num_requests is None:
            return True
        return super().allow_request(request, view)


# ─────────────────────────────────────────────────────
# Anonymous burst throttle
# ─────────────────────────────────────────────────────

class AnonBurstThrottle(AnonRateThrottle):
    """30 anonymous requests per minute."""
    scope = 'anon'
    rate  = '30/min'


# ─────────────────────────────────────────────────────
# Authenticated user sustained throttle
# ─────────────────────────────────────────────────────

class UserSustainedThrottle(RoleAwareRateThrottle):
    """General per-user daily limit, role-scaled."""
    scope        = 'user_sustained'
    viewer_rate  = '500/day'
    analyst_rate = '2000/day'
    admin_rate   = None          # Unlimited


# ─────────────────────────────────────────────────────
# Scan creation throttle
# ─────────────────────────────────────────────────────

class ScanCreateThrottle(RoleAwareRateThrottle):
    """
    Limits how many scans a user can START per hour.
    viewer: 3/h, analyst: 5/h, admin: unlimited
    """
    scope        = 'scan_create'
    viewer_rate  = '3/hour'
    analyst_rate = '5/hour'
    admin_rate   = None

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident,
        }


# ─────────────────────────────────────────────────────
# AI query throttle
# ─────────────────────────────────────────────────────

class AIQueryThrottle(RoleAwareRateThrottle):
    """
    Limits how many AI assistant / remediation calls a user can make per day.
    viewer: 10/d, analyst: 20/d, admin: 200/d
    """
    scope        = 'ai_query'
    viewer_rate  = '10/day'
    analyst_rate = '20/day'
    admin_rate   = '200/day'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident,
        }


# ─────────────────────────────────────────────────────
# Export throttle
# ─────────────────────────────────────────────────────

class ExportThrottle(RoleAwareRateThrottle):
    """
    Limits PDF/CSV/report exports per hour.
    viewer: 1/h, analyst: 3/h, admin: unlimited
    """
    scope        = 'export'
    viewer_rate  = '1/hour'
    analyst_rate = '3/hour'
    admin_rate   = None

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident,
        }


# ─────────────────────────────────────────────────────
# Response header mixin
# ─────────────────────────────────────────────────────

class RateLimitHeaderMixin:
    """
    Mixin for DRF APIView / ViewSet.
    Reads throttle state after allow_request() and attaches
    X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset headers.

    Usage:
        class ScanViewSet(RateLimitHeaderMixin, viewsets.ModelViewSet):
            throttle_classes = [ScanCreateThrottle]
    """

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        try:
            self._inject_rate_limit_headers(request, response)
        except Exception:
            pass  # Never let header injection break the response
        return response

    def _inject_rate_limit_headers(self, request, response):
        throttle_instances = [
            t for t in getattr(self, 'throttle_classes', [])
        ]
        if not throttle_instances:
            return

        # Use the first throttle class to compute headers
        throttle_class = throttle_instances[0]
        throttle = throttle_class()
        throttle.request = request

        rate = throttle.get_rate() if hasattr(throttle, 'get_rate') else getattr(throttle, 'rate', None)
        if not rate:
            return

        num_requests, duration = _parse_rate(rate)
        if num_requests is None:
            return

        cache_key = throttle.get_cache_key(request, None) if hasattr(throttle, 'get_cache_key') else None
        if not cache_key:
            return

        history = cache.get(cache_key, [])
        now = time.time()
        # Clean expired entries
        history = [ts for ts in history if ts > now - duration]

        used      = len(history)
        remaining = max(num_requests - used, 0)
        reset_at  = int(history[0] + duration) if history else int(now + duration)

        response['X-RateLimit-Limit']     = str(num_requests)
        response['X-RateLimit-Remaining'] = str(remaining)
        response['X-RateLimit-Reset']     = str(reset_at)
        response['X-RateLimit-Scope']     = getattr(throttle, 'scope', 'unknown')
