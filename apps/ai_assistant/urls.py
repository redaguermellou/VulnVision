from django.urls import path
from . import views

app_name = 'ai_assistant'

urlpatterns = [
    path('chat/', views.AIAssistantView.as_view(), name='chat'),
    path('api/message/', views.ChatMessageView.as_view(), name='send_message'),
    path('history/', views.ChatHistoryView.as_view(), name='history'),
    path('widget/', views.ChatWidgetView.as_view(), name='widget'),
    path('export/<int:session_id>/', views.ExportChatPdfView.as_view(), name='export'),
    path('remediation/<int:vuln_id>/', views.RemediationGuideView.as_view(), name='remediation_guide'),
    path('remediation/owasp/<int:owasp_id>/', views.RemediationGuideView.as_view(), name='owasp_remediation_guide'),
    path('api/remediation/<int:vuln_id>/generate/', views.GenerateRemediationView.as_view(), name='generate_remediation'),
    path('api/remediation/owasp/<int:owasp_id>/generate/', views.GenerateRemediationView.as_view(), name='generate_owasp_remediation'),
]
