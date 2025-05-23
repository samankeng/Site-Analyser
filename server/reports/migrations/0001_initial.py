# Generated by Django 5.2 on 2025-04-25 17:42

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('target_url', models.URLField(max_length=255)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('scan_types', models.JSONField(default=list)),
                ('highest_severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Informational'), ('none', 'None')], default='none', max_length=20)),
                ('findings_summary', models.JSONField(default=dict)),
                ('results', models.JSONField(default=dict)),
                ('notes', models.TextField(blank=True, null=True)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('pdf_report', models.FileField(blank=True, null=True, upload_to='reports/pdf/')),
                ('export_formats', models.JSONField(default=list)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ReportExport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('format', models.CharField(choices=[('pdf', 'PDF'), ('csv', 'CSV'), ('json', 'JSON'), ('html', 'HTML')], max_length=10)),
                ('file', models.FileField(upload_to='reports/exports/')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('options', models.JSONField(default=dict)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='exports', to='reports.report')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='report_exports', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low'), ('info', 'Informational')], default='low', max_length=20)),
                ('category', models.CharField(max_length=100)),
                ('details', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('false_positive', models.BooleanField(default=False)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vulnerabilities', to='reports.report')),
            ],
            options={
                'ordering': ['severity', 'name'],
            },
        ),
        migrations.AddIndex(
            model_name='report',
            index=models.Index(fields=['user', 'status'], name='reports_rep_user_id_8456e4_idx'),
        ),
        migrations.AddIndex(
            model_name='report',
            index=models.Index(fields=['target_url'], name='reports_rep_target__7a9526_idx'),
        ),
        migrations.AddIndex(
            model_name='report',
            index=models.Index(fields=['created_at'], name='reports_rep_created_a6aabf_idx'),
        ),
        migrations.AddIndex(
            model_name='reportexport',
            index=models.Index(fields=['report', 'format'], name='reports_rep_report__830929_idx'),
        ),
        migrations.AddIndex(
            model_name='reportexport',
            index=models.Index(fields=['user', 'created_at'], name='reports_rep_user_id_e4910f_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['report', 'severity'], name='reports_vul_report__20c96a_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['category'], name='reports_vul_categor_bdce8c_idx'),
        ),
    ]
