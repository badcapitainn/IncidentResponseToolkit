# Generated by Django 5.1.4 on 2025-05-10 09:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('toolkit', '0023_logsource_logalert_logentry'),
    ]

    operations = [
        migrations.CreateModel(
            name='BlockedIP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
                ('blocked_at', models.DateTimeField(auto_now_add=True)),
                ('reason', models.TextField()),
                ('duration_minutes', models.IntegerField(default=60)),
                ('unblocked', models.BooleanField(default=False)),
                ('unblocked_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'ordering': ['-blocked_at'],
            },
        ),
    ]
