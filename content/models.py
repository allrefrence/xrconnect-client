# import your packages for writing and creating your database models for login app
from django.db import models

# Create your models here.


''' creating model for adding   content  with named  ContentModel with below fields  '''


class ContentModel(models.Model):
    content_id = models.CharField(max_length=128)
    content_name = models.CharField(max_length=128)
    content_type = models.CharField(max_length=128)
    thumbnail_path = models.CharField(max_length=128)
    description = models.TextField()
    owner = models.CharField(max_length=128)
    access_type = models.CharField(max_length=128)
    file_path = models.CharField(max_length=300)
    file_name = models.CharField(max_length=128)
    version = models.CharField(max_length=300)
    buildtarget = models.CharField(max_length=200)

    def __str__(self):
        return self.content_name


''' creating model for adding   user content  with named  UserContentModel with below fields  '''


class UserContentModel(models.Model):
    content_id = models.CharField(max_length=128)
    content_name = models.CharField(max_length=528)
    content_type = models.CharField(max_length=128)
    content_load_type = models.CharField(max_length=150)
    thumbnail_path = models.CharField(max_length=500)
    description = models.TextField()
    owner = models.CharField(max_length=200)
    access_type = models.CharField(max_length=128)
    path = models.CharField(max_length=200)
    version = models.CharField(max_length=128)
    file_name = models.CharField(max_length=128)
    build_target = models.CharField(max_length=128)

    def __str__(self):
        return self.content_name
