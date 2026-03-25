import json
import time
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.generic import View, ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .models import ChatSession, ChatMessage, RemediationGuide
from .utils.ai_client import AIClient, format_context
from .utils.remediation_service import RemediationService
from apps.targets.models import Target
from apps.scans.models import Scan, Vulnerability, OWASPAlert
import markdown


def _check_ai_rate_limit(user):
    """
    Simple rate-limit check for AI views (not using DRF throttle middleware).
    Returns (allowed: bool, headers: dict).
    Role-based daily limits: viewer=10, analyst=20, admin=unlimited.
    """
    if user.is_staff:
        return True, {}

    role = getattr(user, 'role', 'viewer')
    limits = {'admin': None, 'analyst': 20, 'viewer': 10}
    limit = limits.get(role, 10)
    if limit is None:
        return True, {}

    duration = 86400  # 1 day in seconds
    cache_key = f"throttle_ai_query_{user.pk}"
    now = time.time()
    history = cache.get(cache_key, [])
    history = [ts for ts in history if ts > now - duration]

    remaining = max(limit - len(history), 0)
    reset_ts  = int(history[0] + duration) if history else int(now + duration)
    headers = {
        'X-RateLimit-Limit':     str(limit),
        'X-RateLimit-Remaining': str(remaining),
        'X-RateLimit-Reset':     str(reset_ts),
        'X-RateLimit-Scope':     'ai_query',
    }

    if len(history) >= limit:
        return False, headers

    history.append(now)
    cache.set(cache_key, history, duration)
    return True, headers


class AIAssistantView(LoginRequiredMixin, View):
    def get(self, request):
        target_id = request.GET.get('target_id')
        scan_id = request.GET.get('scan_id')
        
        target = None
        scan = None
        
        if target_id:
            target = get_object_or_404(Target, id=target_id)
        if scan_id:
            scan = get_object_or_404(Scan, id=scan_id)
            if not target:
                target = scan.target

        # Create or get active session for this context
        session, created = ChatSession.objects.get_or_create(
            user=request.user,
            target=target,
            scan=scan,
            is_active=True,
            defaults={'title': f"Analysis for {target.name if target else 'New Scan'}"}
        )
        
        context = {
            'session': session,
            'target': target,
            'scan': scan,
        }
        context['chat_messages'] = session.messages.all()
        return render(request, 'ai/chat.html', context)

class ChatMessageView(LoginRequiredMixin, View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        # Rate limiting: 10 messages per minute per user
        user_id = request.user.id
        cache_key = f"ai_rate_limit_{user_id}"
        msg_count = cache.get(cache_key, 0)
        
        if msg_count >= 10:
            return JsonResponse({'error': 'Rate limit exceeded. Please wait a minute.'}, status=429)
        
        cache.set(cache_key, msg_count + 1, 60)

        data = json.loads(request.body)
        session_id = data.get('session_id')
        content = data.get('content')
        
        session = get_object_or_404(ChatSession, id=session_id, user=request.user)
        
        # Save user message
        user_message = ChatMessage.objects.create(
            session=session,
            role='user',
            content=content
        )
        
        # Prepare context
        vulns = None
        if session.scan:
            vulns = session.scan.vulnerabilities.all()
        elif session.target:
            vulns = session.target.vulnerabilities.all()
            
        context_text = format_context(target=session.target, scan=session.scan, vulnerabilities=vulns)
        
        # Get AI response
        ai_client = AIClient()
        history = list(session.messages.all().values('role', 'content'))
        
        ai_response_content = ai_client.get_response(history, context_text)
        
        # Save AI message
        ai_message = ChatMessage.objects.create(
            session=session,
            role='assistant',
            content=ai_response_content
        )
        
        # Generate suggested questions
        suggestions = ai_client.generate_suggested_questions(context_text + f"\nUser asked: {content}")
        
        return JsonResponse({
            'role': 'assistant',
            'content': markdown.markdown(ai_message.content),
            'raw_content': ai_message.content,
            'suggestions': suggestions
        })

class ChatHistoryView(LoginRequiredMixin, ListView):
    model = ChatSession
    template_name = 'ai/chat_history.html'
    context_object_name = 'sessions'
    
    def get_queryset(self):
        return ChatSession.objects.filter(user=self.request.user).order_by('-updated_at')

class ChatWidgetView(LoginRequiredMixin, View):
    def get(self, request):
        target_id = request.GET.get('target_id')
        scan_id = request.GET.get('scan_id')
        
        target = None
        scan = None
        
        if target_id:
            target = get_object_or_404(Target, id=target_id)
        if scan_id:
            scan = get_object_or_404(Scan, id=scan_id)
            if not target:
                target = scan.target

        session, created = ChatSession.objects.get_or_create(
            user=request.user,
            target=target,
            scan=scan,
            is_active=True,
            defaults={'title': f"Quick Chat - {target.name if target else 'General'}"}
        )
        
        context = {
            'session': session,
            'target': target,
            'scan': scan,
        }
        return render(request, 'ai/chat_widget.html', context)

class ExportChatPdfView(LoginRequiredMixin, View):
    def get(self, request, session_id):
        session = get_object_or_404(ChatSession, id=session_id, user=request.user)
        # For now, we'll return a simple text-based "PDF" or HTML that can be printed.
        # Real PDF export usually needs weasyprint or reportlab.
        # I'll implement a clean HTML page designed for printing.
        
        context = {
            'session': session,
            'chat_messages': session.messages.all(),
        }
        return render(request, 'ai/chat_export.html', context)

class RemediationGuideView(LoginRequiredMixin, View):
    def get(self, request, vuln_id=None, owasp_id=None):
        if vuln_id:
            obj = get_object_or_404(Vulnerability, id=vuln_id)
        else:
            obj = get_object_or_404(OWASPAlert, id=owasp_id)
        
        # Check if guide exists
        guide = getattr(obj, 'ai_remediation', None)
        
        if not guide:
            service = RemediationService()
            guide = service.generate_guide(obj)
            
        context = {
            'object': obj,
            'is_owasp': bool(owasp_id),
            'guide': guide,
        }
        return render(request, 'ai/remediation_detail.html', context)

class GenerateRemediationView(LoginRequiredMixin, View):
    def post(self, request, vuln_id=None, owasp_id=None):
        if vuln_id:
            obj = get_object_or_404(Vulnerability, id=vuln_id)
        else:
            obj = get_object_or_404(OWASPAlert, id=owasp_id)
            
        service = RemediationService()
        guide = service.generate_guide(obj)
        
        if guide:
            return JsonResponse({
                'status': 'success',
                'html': guide.html_content,
                'version': guide.version
            })
        return JsonResponse({'status': 'error', 'message': 'Failed to generate guide'}, status=500)
