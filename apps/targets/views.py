import csv
import io
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.views.generic import ListView, CreateView, DetailView, UpdateView, DeleteView, FormView, View
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from .models import Target
from .forms import TargetImportForm
from django.apps import apps

class TargetListView(LoginRequiredMixin, ListView):
    model = Target
    template_name = 'targets/target_list.html'
    context_object_name = 'targets'
    paginate_by = 10

    def get_queryset(self):
        queryset = Target.objects.filter(user=self.request.user)
        query = self.request.GET.get('q')
        tag = self.request.GET.get('tag')
        
        if query:
            queryset = queryset.filter(
                Q(name__icontains=query) | Q(url__icontains=query)
            )
        if tag:
            queryset = queryset.filter(tags__icontains=tag)
            
        return queryset

class TargetCreateView(LoginRequiredMixin, CreateView):
    model = Target
    fields = ['name', 'url', 'ip_address', 'description', 'protocol', 'is_active', 'tags']
    template_name = 'targets/target_form.html'
    success_url = reverse_lazy('targets:target_list')

    def form_valid(self, form):
        form.instance.user = self.request.user
        messages.success(self.request, f"Target '{form.instance.name}' created successfully.")
        return super().form_valid(form)

class TargetDetailView(LoginRequiredMixin, DetailView):
    model = Target
    template_name = 'targets/target_detail.html'
    context_object_name = 'target'

class TargetUpdateView(LoginRequiredMixin, UpdateView):
    model = Target
    fields = ['name', 'url', 'ip_address', 'description', 'protocol', 'is_active', 'tags']
    template_name = 'targets/target_form.html'
    success_url = reverse_lazy('targets:target_list')

    def form_valid(self, form):
        messages.success(self.request, f"Target '{form.instance.name}' updated successfully.")
        return super().form_valid(form)

class TargetDeleteView(LoginRequiredMixin, DeleteView):
    model = Target
    template_name = 'targets/target_confirm_delete.html'
    success_url = reverse_lazy('targets:target_list')

    def delete(self, request, *args, **kwargs):
        target = self.get_object()
        messages.success(self.request, f"Target '{target.name}' deleted successfully.")
        return super().delete(request, *args, **kwargs)

@login_required
def export_targets_csv(request):
    targets = Target.objects.filter(user=request.user)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vulnvision_targets_export.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['name', 'url', 'ip_address', 'description', 'protocol', 'is_active', 'tags'])
    
    for target in targets:
        writer.writerow([
            target.name,
            target.url,
            target.ip_address,
            target.description,
            target.protocol,
            target.is_active,
            target.tags
        ])
    
    return response

@login_required
def download_csv_template(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="target_import_template.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['name', 'url', 'ip_address', 'description', 'protocol', 'is_active', 'tags'])
    writer.writerow(['Example Target', 'https://example.com', '192.168.1.1', 'A sample target', 'https', 'True', 'web,test'])
    
    return response

class TargetImportView(LoginRequiredMixin, FormView):
    template_name = 'targets/target_import.html'
    form_class = TargetImportForm
    success_url = reverse_lazy('targets:target_list')

    def form_valid(self, form):
        csv_file = self.request.FILES['csv_file']
        handle_duplicates = form.cleaned_data['handle_duplicates']
        
        decoded_file = csv_file.read().decode('utf-8')
        io_string = io.StringIO(decoded_file)
        reader = csv.DictReader(io_string)
        
        preview_data = []
        for row in reader:
            preview_data.append(row)
        
        # Store in session for preview/process
        self.request.session['import_data'] = preview_data
        self.request.session['import_handle_duplicates'] = handle_duplicates
        
        return render(self.request, 'targets/target_import_preview.html', {
            'preview_data': preview_data,
            'handle_duplicates': handle_duplicates
        })

class TargetImportProcessView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        import_data = request.session.get('import_data')
        handle_duplicates = request.session.get('import_handle_duplicates', 'skip')
        
        if not import_data:
            messages.error(request, "No import data found.")
            return redirect('targets:target_import')
        
        success_count = 0
        update_count = 0
        error_count = 0
        errors = []
        
        for row in import_data:
            try:
                name = row.get('name')
                url = row.get('url')
                if not name or not url:
                    raise ValueError("Name and URL are required.")
                
                target, created = Target.objects.get_or_create(
                    user=request.user,
                    url=url,
                    defaults={
                        'name': name,
                        'ip_address': row.get('ip_address'),
                        'description': row.get('description', ''),
                        'protocol': row.get('protocol', 'https'),
                        'is_active': row.get('is_active', 'True').lower() == 'true',
                        'tags': row.get('tags', '')
                    }
                )
                
                if created:
                    success_count += 1
                elif handle_duplicates == 'update':
                    target.name = name
                    target.ip_address = row.get('ip_address')
                    target.description = row.get('description', '')
                    target.protocol = row.get('protocol', 'https')
                    target.is_active = row.get('is_active', 'True').lower() == 'true'
                    target.tags = row.get('tags', '')
                    target.save()
                    update_count += 1
                else:
                    # Skip or duplicate check (here we check by URL per user)
                    pass
                    
            except Exception as e:
                error_count += 1
                errors.append(f"Row {row}: {str(e)}")
        
        # Clear session
        del request.session['import_data']
        if 'import_handle_duplicates' in request.session:
            del request.session['import_handle_duplicates']
            
        return render(request, 'targets/target_import_result.html', {
            'success_count': success_count,
            'update_count': update_count,
            'error_count': error_count,
            'errors': errors
        })

class TargetScanTriggerView(LoginRequiredMixin, View):
    def post(self, request, pk):
        target = get_object_or_404(Target, pk=pk, user=request.user)
        
        # Avoid circular import by fetching model dynamically
        Scan = apps.get_model('scans', 'Scan')
        from apps.scans.tasks import run_scan_task
        
        scan_name = f"Quick Assessment - {target.name} - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
        
        scan = Scan.objects.create(
            user=request.user,
            target=target,
            name=scan_name,
            scan_type='full',
            status='pending'
        )
        
        try:
            run_scan_task.delay(scan.id)
            messages.success(request, f"Scan '{scan.name}' has been initiated for {target.name}.")
        except Exception as e:
            messages.warning(request, f"Scan '{scan.name}' created but couldn't be queued. Is Celery running?")
            
        return redirect('scans:scan_detail', pk=scan.id)

