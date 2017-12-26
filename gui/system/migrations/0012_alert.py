# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2017-12-12 15:36
from __future__ import unicode_literals

from django.db import migrations, models
import freenasUI.freeadmin.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0011_alert_default_settings'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Alert',
        ),
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('node', models.CharField(default='A', max_length=100)),
                ('source', models.TextField()),
                ('key', models.TextField()),
                ('datetime', models.DateTimeField()),
                ('level', models.IntegerField()),
                ('title', models.TextField()),
                ('args', freenasUI.freeadmin.models.fields.DictField()),
                ('dismissed', models.BooleanField()),
            ],
        ),
        migrations.AlterUniqueTogether(
            name='alert',
            unique_together=set([('node', 'source', 'key')]),
        ),
    ]
