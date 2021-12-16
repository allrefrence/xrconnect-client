# creating serializers for login app and models
from rest_framework import serializers
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from .models import RegisterModel, SessionModel, Session_Users, Media, Session_Media
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
import socket

sender_address = 'support@xrconnect.io'
sender_pass = 'support@!23'
socket.getaddrinfo('localhost', 8080)
''' creating serializer class for RegisterModel with named 
RegistrationSerializer with below criteria '''


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = RegisterModel
        fields = (
            'id',
            'user_name',
            'email',
            'password',
            'gender',
            'role',
            # 'system_ID',
            "image_path",
            # "login_status",
            # "is_social_user"
        )

        extra_kwargs = {"password_hash": {"write_only": True}}

    # def validate(self, attrs):
    #     email = attrs.get('email', '')
    #     user_name = attrs.get('user_name', '')

        # if not user_name.isalnum():
        #     raise serializers.ValidationError(
        #         self.default_error_messages)
        # return attrs

    def create(self, validated_data):
        return RegisterModel.objects.create_user(**validated_data)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    user_name = serializers.CharField(
        max_length=255, min_length=3, read_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = RegisterModel.objects.get(email=obj['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = RegisterModel
        fields = ['email', 'password', 'user_name', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        filtered_user_by_email = RegisterModel.objects.filter(email=email)
        user = auth.authenticate(email=email, password=password)
        # user_data = RegisterModel.objects.get(email=email)
        # active = user_data.is_active

        if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)
        userdata = RegisterModel.objects.filter(email=email)
        print('------')
        print(userdata.get().email)
        print(userdata.get().is_active)
        if userdata.get().is_active:
            if not user:
                raise AuthenticationFailed('Invalid credentials, try again')

            return {
                'email': user.email,
                'username': user.user_name,
                'tokens': user.tokens
            }
        else:
            return super().validate(attrs)


''' creating serializer class for RegisterModel with named EmailVerificationSerializer
'''


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = RegisterModel
        fields = ['token']


''' creating serializer class for SessionModel with named 
SessionSerializers with below criteria '''


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=3)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = RegisterModel.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()
            return user


        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class SessionSerializers(serializers.ModelSerializer):
    class Meta:
        model = SessionModel
        fields = ['id', 'session_id', 'date_created', 'event_name', 'event_type', 'parent_event_name', 'access_type',
                  'max_users', 'created_by', 'description', 'environment_id', 'category', 'content']


''' creating serializer class for Session_Users with named 
SessionUserSerializers with below criteria '''


class SessionUserSerializers(serializers.ModelSerializer):
    class Meta:
        model = Session_Users
        fields = "__all__"


''' creating serializer class for Media with named 
MediaSerializers with below criteria '''


class MediaSerializers(serializers.ModelSerializer):
    class Meta:
        model = Media
        fields = ['media_id', 'media_type', 'thumbnail_path', 'description', 'owner', 'upload_by', 'access_type',
                  'permitted_users', 'path', 'version']


''' creating serializer class for Session_Media with named 
Session_mediaSerializers with below criteria '''


class Session_mediaSerializers(serializers.ModelSerializer):
    class Meta:
        model = Session_Media
        fields = "__all__"
