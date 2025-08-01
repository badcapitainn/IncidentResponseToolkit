# Generated by Django 5.1.4 on 2025-05-03 10:36

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('toolkit', '0016_alter_networkalert_options_alter_networkrule_options_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(
            model_name='networkalert',
            name='rule',
        ),
        migrations.AlterModelOptions(
            name='networkalert',
            options={'ordering': ['-timestamp']},
        ),
        migrations.AlterModelOptions(
            name='networktraffic',
            options={'ordering': ['-timestamp']},
        ),
        migrations.RenameField(
            model_name='networkalert',
            old_name='description',
            new_name='message',
        ),
        migrations.RenameField(
            model_name='networkalert',
            old_name='created_at',
            new_name='timestamp',
        ),
        migrations.RenameField(
            model_name='networktraffic',
            old_name='is_malicious',
            new_name='flagged',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='status',
        ),
        migrations.RemoveField(
            model_name='networkalert',
            name='traffic',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='flags',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='matched_rule',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='payload',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='port',
        ),
        migrations.RemoveField(
            model_name='networktraffic',
            name='threat_type',
        ),
        migrations.AddField(
            model_name='networkalert',
            name='alert_type',
            field=models.CharField(default='GenericAlert', max_length=100),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='packet_data',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networkalert',
            name='resolved',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='alert',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='toolkit.networkalert'),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='destination_port',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='networktraffic',
            name='source_port',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='networkalert',
            name='resolved_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='networkalert',
            name='severity',
            field=models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], max_length=10),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='packet_size',
            field=models.IntegerField(),
        ),
        migrations.AlterField(
            model_name='networktraffic',
            name='protocol',
            field=models.CharField(choices=[('tcp', 'TCP'), ('udp', 'UDP'), ('icmp', 'ICMP'), ('other', 'Other')], max_length=10),
        ),
        migrations.DeleteModel(
            name='NetworkRule',
        ),
    ]
