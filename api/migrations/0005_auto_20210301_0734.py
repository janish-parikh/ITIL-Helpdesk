# Generated by Django 2.2.18 on 2021-03-01 02:04

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_auto_20210223_1803'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='kbitem',
            name='recommendations',
        ),
        migrations.RemoveField(
            model_name='kbitem',
            name='votes',
        ),
    ]