# Generated by Django 4.0.4 on 2022-05-16 05:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_customuser_blood_group'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='available',
            field=models.BooleanField(default=False, null=True),
        ),
    ]
