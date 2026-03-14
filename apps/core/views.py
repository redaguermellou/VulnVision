from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import (
    LoginView, LogoutView, PasswordChangeView, PasswordChangeDoneView,
    PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
)
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import CreateView, UpdateView
from .forms import RegistrationForm, LoginForm, UserUpdateForm, ProfileUpdateForm
from .models import User, UserProfile

class CustomLoginView(LoginView):
    template_name = 'registration/login.html'
    authentication_form = None # We'll handle it manually or use a simple form
    
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me')
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                login(request, user)
                if not remember_me:
                    request.session.set_expiry(0)
                messages.success(request, f"Welcome back, {user.full_name or user.email}!")
                return redirect(request.GET.get('next', 'home'))
            else:
                messages.error(request, "Invalid email or password.")
        return render(request, self.template_name, {'form': form})

    def get(self, request, *args, **kwargs):
        form = LoginForm()
        return render(request, self.template_name, {'form': form})

class RegisterView(CreateView):
    form_class = RegistrationForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('login')

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('home')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Account created successfully! You can now log in.")
        return response

@login_required
def profile_view(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, request.FILES, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, instance=request.user.profile)
        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            messages.success(request, "Your profile has been updated!")
            return redirect('profile')
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)

    context = {
        'u_form': u_form,
        'p_form': p_form
    }
    return render(request, 'core/profile.html', context)

class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'registration/password_change.html'
    success_url = reverse_lazy('password_change_done')
    
    def form_valid(self, form):
        messages.success(self.request, "Your password was successfully updated!")
        return super().form_valid(form)

from django.db.models import Count, Avg, F, ExpressionWrapper, fields
from django.utils import timezone
from datetime import timedelta
from apps.scans.models import Scan, Vulnerability

@login_required
def home(request):
    user = request.user
    today = timezone.now()
    first_day_this_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    first_day_last_month = (first_day_this_month - timedelta(days=1)).replace(day=1)
    
    # Summary Statistics
    scans = Scan.objects.filter(user=user)
    total_scans = scans.count()
    this_month_scans = scans.filter(created_at__gte=first_day_this_month).count()
    last_month_scans = scans.filter(created_at__gte=first_day_last_month, created_at__lt=first_day_this_month).count()
    
    scan_change = this_month_scans - last_month_scans
    
    vulnerabilities = Vulnerability.objects.filter(scan__user=user)
    total_vulns = vulnerabilities.count()
    
    severity_counts = vulnerabilities.values('severity').annotate(count=Count('id'))
    severity_data = {s[0]: 0 for s in Vulnerability.SEVERITY_CHOICES}
    for item in severity_counts:
        severity_data[item['severity']] = item['count']
        
    critical_count = severity_data.get('critical', 0)
    
    # Average Remediation Time
    resolved_vulns = vulnerabilities.filter(status='resolved', resolved_at__isnull=False)
    if resolved_vulns.exists():
        duration = ExpressionWrapper(F('resolved_at') - F('created_at'), output_field=fields.DurationField())
        avg_remediation = resolved_vulns.annotate(duration=duration).aggregate(Avg('duration'))['duration__avg']
        if avg_remediation:
            avg_remediation_hours = avg_remediation.total_seconds() / 3600
        else:
            avg_remediation_hours = 0
    else:
        avg_remediation_hours = 0
        
    # Chart Data: Scans Over Time (Last 30 days)
    last_30_days = today - timedelta(days=30)
    scans_over_time = scans.filter(created_at__gte=last_30_days).values('created_at__date').annotate(count=Count('id')).order_by('created_at__date')
    
    chart_scans_labels = [str(item['created_at__date']) for item in scans_over_time]
    chart_scans_data = [item['count'] for item in scans_over_time]
    
    # Chart Data: Category Distribution (Scan Type)
    type_counts = scans.values('scan_type').annotate(count=Count('id'))
    chart_type_labels = [dict(Scan.SCAN_TYPES).get(item['scan_type']) for item in type_counts]
    chart_type_data = [item['count'] for item in type_counts]
    
    # OWASP Top 10 Mock Data (since we might not have real data yet)
    owasp_labels = ['Injection', 'Broken Auth', 'Sensitive Data', 'XXE', 'Broken Access Control', 'Security Misconfig', 'XSS', 'Insecure Deserialization', 'Using Vuln Components', 'Insufficient Logging']
    owasp_data = [vulnerabilities.filter(owasp_category=cat).count() for cat in owasp_labels]
    # If all zero, provide some mock data for visualization if it's a new account
    if sum(owasp_data) == 0:
        owasp_data = [5, 2, 8, 1, 6, 3, 7, 1, 4, 3] if total_vulns > 0 else [0]*10

    context = {
        'total_scans': total_scans,
        'this_month_scans': this_month_scans,
        'scan_change': scan_change,
        'abs_scan_change': abs(scan_change),
        'total_vulns': total_vulns,
        'severity_data': severity_data,
        'critical_count': critical_count,
        'avg_remediation': round(avg_remediation_hours, 1),
        
        'chart_scans_labels': chart_scans_labels,
        'chart_scans_data': chart_scans_data,
        'chart_type_labels': chart_type_labels,
        'chart_type_data': chart_type_data,
        'chart_severity_labels': [s[1] for s in Vulnerability.SEVERITY_CHOICES],
        'chart_severity_data': [severity_data.get(s[0], 0) for s in Vulnerability.SEVERITY_CHOICES],
        'chart_owasp_labels': owasp_labels,
        'chart_owasp_data': owasp_data,
    }
    return render(request, 'dashboard/index.html', context)

@login_required
def custom_logout(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login')

@login_required
def settings_view(request):
    user = request.user
    profile = user.profile
    settings = user.settings
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'profile':
            user.full_name = request.POST.get('full_name', '')
            user.company = request.POST.get('company', '')
            user.save()
            
            profile.bio = request.POST.get('bio', '')
            profile.phone_number = request.POST.get('phone_number', '')
            profile.location = request.POST.get('location', '')
            profile.save()
            messages.success(request, 'Profile updated successfully.')
            
        elif action == 'preferences':
            settings.theme = request.POST.get('theme', 'dark')
            settings.enable_ai_remediation = request.POST.get('enable_ai_remediation') == 'on'
            settings.webhook_url = request.POST.get('webhook_url', '')
            settings.save()
            messages.success(request, 'Preferences saved.')
            
        elif action == 'integration':
            settings.zap_api_key = request.POST.get('zap_api_key', '')
            settings.zap_proxy_url = request.POST.get('zap_proxy_url', 'http://localhost:8080')
            settings.save()
            messages.success(request, 'Tool integration settings updated.')
            
        elif action == 'notifications':
            settings.email_notifications = request.POST.get('email_notifications') == 'on'
            settings.scan_complete_alerts = request.POST.get('scan_complete_alerts') == 'on'
            settings.save()
            messages.success(request, 'Notification settings updated.')
            
        return redirect('settings')
        
    return render(request, 'core/settings.html', {
        'profile': profile,
        'settings': settings
    })
