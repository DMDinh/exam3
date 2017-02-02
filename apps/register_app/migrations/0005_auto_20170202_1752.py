# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-02 17:52
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('register_app', '0004_friend'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='friend',
            name='user',
        ),
        migrations.AddField(
            model_name='friend',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='register_app.User'),
        ),
    ]
