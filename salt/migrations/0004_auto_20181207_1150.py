# Generated by Django 2.2 on 2018-12-07 03:50

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('salt', '0003_auto_20181207_1106'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='c_time',
            field=models.DateTimeField(default=datetime.datetime(2018, 12, 7, 11, 50, 5, 21016)),
        ),
    ]
