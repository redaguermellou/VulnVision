from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_type', models.CharField(
                    max_length=20,
                    choices=[
                        ('executive', 'Executive Summary'),
                        ('technical', 'Technical Report'),
                        ('compliance_pci', 'PCI-DSS Compliance Report'),
                        ('compliance_iso', 'ISO 27001 Compliance Report'),
                    ],
                    default='technical',
                )),
                ('title', models.CharField(max_length=255)),
                ('status', models.CharField(
                    max_length=20,
                    choices=[
                        ('pending', 'Pending'),
                        ('generating', 'Generating'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                    ],
                    default='pending',
                )),
                ('pdf_file', models.FileField(upload_to='reports/%Y/%m/', blank=True, null=True)),
                ('file_size', models.PositiveIntegerField(null=True, blank=True, help_text='File size in bytes')),
                ('filters', models.JSONField(default=dict, blank=True, help_text='Applied report filters')),
                ('error_message', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(null=True, blank=True)),
                ('user', models.ForeignKey(
                    settings.AUTH_USER_MODEL,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='reports',
                )),
                ('scan', models.ForeignKey(
                    'scans.Scan',
                    on_delete=django.db.models.deletion.SET_NULL,
                    null=True, blank=True,
                    related_name='reports',
                )),
            ],
            options={
                'ordering': ['-created_at'],
                'verbose_name': 'Report',
                'verbose_name_plural': 'Reports',
            },
        ),
    ]
