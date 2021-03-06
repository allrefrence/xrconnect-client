import datetime

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class MyAccountManager(BaseUserManager):
    def create_user(self, email, user_name, password=None
                    ):
        if not email:
            raise ValueError('Users must have an email address')
        if not user_name:
            raise ValueError('user must have user_name')

        user = self.model(
            email=self.normalize_email(email),

        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        user = self.create_user(
            email=self.normalize_email(email),
            password=password,
        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)


class RegisterModel(AbstractBaseUser):
    id = models.BigAutoField(primary_key=True)
    user_name = models.CharField(max_length=128, null=True)
    email = models.CharField(max_length=128, unique=True)
    password = models.CharField(max_length=128, null=True)
    gender = models.CharField(max_length=20, )
    is_active = models.BooleanField(default=False)
    #login_status = models.BooleanField(default=False)
    company_name = models.CharField(max_length=128, default='xrconnect-client')
    role = models.CharField(max_length=30, null=True)
    # token = models.CharField(max_length=30,null=True)
    # system_ID = models.CharField(max_length=30, null=True)
    #login_status = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now_add=True, null=True)
    #is_social_user = models.BooleanField(default=False)
    provider = models.CharField(max_length=128, default='xrconnect-client')
    image_path = models.CharField(max_length=128, null=True)
    USERNAME_FIELD = 'email'

    objects = MyAccountManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        db_table = "tbl.RegisterModel"

    def __str__(self):
        return str(self.email)

    def has_perm(self, perm, obj=None): return self.is_active

    def has_module_perms(self, app_label): return self.is_active


class SessionModel(models.Model):
    date_created = models.CharField(max_length=50)
    date_modified = models.CharField(max_length=50, default=datetime.date.today())
    session_id = models.CharField(max_length=128, unique=True)
    event_name = models.CharField(max_length=128, unique=True)
    event_type = models.CharField(max_length=128)
    parent_event_name = models.CharField(max_length=128)
    session_status = models.BooleanField(default=True)
    access_type = models.CharField(max_length=128)
    max_users = models.CharField(max_length=10)
    host_user_email = models.EmailField(null=True)
    start_date = models.CharField(max_length=50, default=datetime.date.today())
    end_date = models.CharField(max_length=50, default=datetime.date.today())
    description = models.CharField(max_length=1000)
    environment_id = models.CharField(max_length=128)
    category = models.CharField(max_length=128)
    content = models.CharField(max_length=1000)

    def __str__(self):
        return self.event_name


class Session_Users(models.Model):
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now_add=True)
    session_id = models.CharField(max_length=128)
    user_id = models.CharField(max_length=128)
    user_role = models.CharField(max_length=128)
    user_avatar = models.CharField(max_length=1028)
    is_favourite = models.BooleanField(default=False)

    def __str__(self):
        return self.session_id


class Media(models.Model):
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now_add=True)
    media_id = models.CharField(max_length=128, unique=True)
    media_type = models.CharField(max_length=128)
    thumbnail_path = models.CharField(max_length=128)
    description = models.TextField()
    owner = models.CharField(max_length=128)
    upload_by = models.CharField(max_length=128)
    access_type = models.CharField(max_length=128)
    permitted_users = models.CharField(max_length=128)
    path = models.CharField(max_length=128)
    version = models.CharField(max_length=128)

    # file_name = models.CharField(max_length=128)

    def __str__(self):
        return self.media_id


class Session_Media(models.Model):
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now_add=True)
    session_id = models.CharField(max_length=128)
    media_id = models.CharField(max_length=128)
    media_type = models.CharField(max_length=128)
    media_path = models.CharField(max_length=1028)

    def __str__(self):
        return self.media_path
