# Generated by Django 5.0.3 on 2024-03-14 07:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0003_alter_phonenumber_phone_number'),
    ]

    operations = [
        migrations.AlterField(
            model_name='phonenumber',
            name='phone_number',
            field=models.CharField(max_length=20),
        ),
    ]
