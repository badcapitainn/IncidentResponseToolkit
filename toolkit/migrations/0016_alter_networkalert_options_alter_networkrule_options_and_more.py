# Generated by Django 5.1.4 on 2025-04-27 13:22

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('toolkit', '0015_networkalert_networkrule_networktraffic_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='networkalert',
            options={'ordering': ['-created_at']},
        ),
        migrations.AlterModelOptions(
            name='networkrule',
            options={'ordering': ['-created_at']},
        ),
        migrations.AlterModelOptions(
            name='networktraffic',
            options={'ordering': ['-timestamp'], 'verbose_name_plural': 'Network Traffic'},
        ),
        migrations.RenameField(
            model_name='networkalert',
            old_name='timestamp',
            new_name='created_at',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='alert_type',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='destination_ip',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='is_resolved',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='rule_triggered',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='source_ip',
        ),
        migrations.RemoveField(
            model_name='networkrule',
            name='definition',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='length',
        ),
        migrations.AddField(
            model_name='networkalert',
            name='resolved_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='resolved_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='resolved_alerts', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='rule',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='toolkit.networkrule'),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='status',
            field=models.CharField(choices=[('open', 'Open'), ('investigating', 'Investigating'), ('resolved', 'Resolved'), ('false_positive', 'False Positive')], default='open', max_length=15),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='traffic',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='toolkit.networktraffic'),
        ),
        migrations.AddField(
            model_name='networkrule',
            name='action',
            field=models.CharField(choices=[('ALERT', 'Generate Alert'), ('BLOCK', 'Block Traffic'), ('LOG', 'Log Only')], max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='networkrule',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='networkrule',
            name='pattern',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='networkrule',
            name='severity',
            field=models.CharField(default='medium', max_length=20),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='matched_rule',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='packet_size',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='payload',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='networkrule',
            name='name',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='networkrule',
            name='rule_type',
            field=models.CharField(choices=[('IP', 'IP Address'), ('PORT', 'Port'), ('PAYLOAD', 'Payload Content'), ('SIZE', 'Packet Size'), ('FLAG', 'TCP Flags'), ('RATE', 'Traffic Rate')], max_length=10),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='destination_ip',
            field=models.CharField(max_length=45),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='flags',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='port',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='source_ip',
            field=models.CharField(max_length=45),
        ),
    ]
