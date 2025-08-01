# Generated by Django 5.1.4 on 2025-06-15 08:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('toolkit', '0029_networkalert_resolution_networkalert_resolved_at_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_type', models.CharField(choices=[('THREAT_SUMMARY', 'Periodic Threat Summary'), ('THREAT_INTEL', 'Threat Intelligence Report'), ('SYSTEM_SAFETY', 'System Safety Summary')], max_length=20)),
                ('title', models.CharField(max_length=255)),
                ('generated_at', models.DateTimeField(auto_now_add=True)),
                ('start_date', models.DateTimeField()),
                ('end_date', models.DateTimeField()),
                ('data', models.JSONField(default=dict)),
                ('pdf_file', models.FileField(blank=True, null=True, upload_to='reports/pdf/')),
                ('generated_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-generated_at'],
            },
        ),
    ]
