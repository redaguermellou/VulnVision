import os
from django.apps import AppConfig


class AiAssistantConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.ai_assistant'
    path = os.path.dirname(os.path.abspath(__file__))
