"""
Custom API Key authentication for VulnVision.
Reads the key from:
  - HTTP Header: X-API-Key: <key>
  - Query param:  ?api_key=<key>
"""
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model

User = get_user_model()


class APIKeyAuthentication(BaseAuthentication):
    keyword = 'X-API-Key'

    def authenticate(self, request):
        # 1. Try header first
        api_key = request.META.get('HTTP_X_API_KEY')
        # 2. Fall back to query param
        if not api_key:
            api_key = request.query_params.get('api_key')

        if not api_key:
            return None  # Let next auth class try

        try:
            user = User.objects.get(api_key=api_key, is_active=True)
        except User.DoesNotExist:
            raise AuthenticationFailed('Invalid API key.')

        return (user, None)

    def authenticate_header(self, request):
        return self.keyword
