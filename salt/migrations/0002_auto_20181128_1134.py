# Generated by Django 2.2 on 2018-11-28 03:34

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('salt', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='c_time',
            field=models.DateTimeField(default=datetime.datetime(2018, 11, 28, 11, 34, 44, 594072)),
        ),
    ]
