from django.urls import path
from . import views

app_name = 'targets'

urlpatterns = [
    path('', views.TargetListView.as_view(), name='target_list'),
    path('create/', views.TargetCreateView.as_view(), name='target_create'),
    path('<int:pk>/', views.TargetDetailView.as_view(), name='target_detail'),
    path('<int:pk>/update/', views.TargetUpdateView.as_view(), name='target_update'),
    path('<int:pk>/delete/', views.TargetDeleteView.as_view(), name='target_delete'),
    
    # Import/Export
    path('export/', views.export_targets_csv, name='target_export'),
    path('import/', views.TargetImportView.as_view(), name='target_import'),
    path('import/process/', views.TargetImportProcessView.as_view(), name='target_import_process'),
    path('template/', views.download_csv_template, name='target_template'),
]
