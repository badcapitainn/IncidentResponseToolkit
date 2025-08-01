# Generated by Django 5.1.4 on 2025-02-04 17:25

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AlertLogs',
            fields=[
                ('log_Id', models.AutoField(primary_key=True, serialize=False)),
                ('timeStamp', models.DateTimeField()),
                ('message', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='ResourceUsageLogs',
            fields=[
                ('log_Id', models.AutoField(primary_key=True, serialize=False)),
                ('timeStamp', models.DateTimeField()),
                ('message', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='SuspiciousLogs',
            fields=[
                ('log_Id', models.AutoField(primary_key=True, serialize=False)),
                ('timeStamp', models.DateTimeField()),
                ('message', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='WatchlistLogs',
            fields=[
                ('log_Id', models.AutoField(primary_key=True, serialize=False)),
                ('timeStamp', models.DateTimeField()),
                ('message', models.TextField()),
            ],
        ),
    ]
