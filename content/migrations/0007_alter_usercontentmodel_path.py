# Generated by Django 3.2.9 on 2021-12-02 11:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('content', '0006_rename_contnet_name_usercontentmodel_content_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usercontentmodel',
            name='path',
            field=models.CharField(max_length=200),
        ),
    ]