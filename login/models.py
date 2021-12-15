# import your packages for writing and creating your database models for login app
import datetime
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken

''' Base-users model manager for Register model with named MyAccountManager '''


class MyAccountManager(BaseUserManager):
    def create_user(self, user_name, email, gender, role, image_path, password=None):
        if user_name is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(user_name=user_name, gender=gender, role=role, image_path=image_path,
                          email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, user_name, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(user_name, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}

''' creating AbstractBaseUsermod for register the users with RegisterModel with below fields  '''


class RegisterModel(AbstractBaseUser):
    id = models.BigAutoField(primary_key=True)
    user_name = models.CharField(max_length=128, null=True)
    email = models.CharField(max_length=128, unique=True)
    password = models.CharField(max_length=128, null=True)
    gender = models.CharField(max_length=20, )
    is_active = models.BooleanField(default=False)
    # login_status = models.BooleanField(default=False)
    company_name = models.CharField(max_length=128, default='xrconnect-client')
    role = models.CharField(max_length=30, null=True)
    # token = models.CharField(max_length=30,null=True)
    # system_ID = models.CharField(max_length=30, null=True)
    # login_status = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now_add=True, null=True)
    # is_social_user = models.BooleanField(default=False)
    provider = models.CharField(max_length=128, default='xrconnect-client')
    image_path = models.CharField(max_length=128, null=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))
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


''' creating model for adding sessions  with named  SessionModel with below fields  '''


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


''' creating model for adding sessions  with named  Session_Users with below fields  '''


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


''' creating model for adding sessions  with named  Media with below fields  '''


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


''' creating model for adding sessions  with named  Session_Media with below fields   '''


class Session_Media(models.Model):
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now_add=True)
    session_id = models.CharField(max_length=128, unique=True)
    media_id = models.CharField(max_length=128)
    media_type = models.CharField(max_length=128)
    media_path = models.CharField(max_length=1028)

    def __str__(self):
        return self.media_path
