import jwt
from django.contrib.auth.models import User
from rest_framework import authentication
from django.conf import settings
# from .models import RegisterModel
from rest_framework_simplejwt import exceptions


class JWTAuthentication(authentication.BasicAuthentication):
    def authenticate(self, request):
        auth_data = authentication.get_authorization_header(request)
        if not auth_data:
            return None
        prefix, token = auth_data.decode('utf-8').split(' ')
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY)
            user = User.objects.get(user_name=payload['user_name'])
            return (user, token)
        except jwt.DecodeError as identifier:
            raise exceptions.AuthenticationFailed('your token is invalid,login')
        except jwt.ExpiredSignatureError as identifier:
            raise exceptions.AuthenticationFailed('your token is expired,login')
        return super().authenticate(request)
