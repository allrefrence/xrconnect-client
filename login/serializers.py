# creating serializers for login app and models
from rest_framework import serializers
from .models import RegisterModel, SessionModel, Session_Users, Media, Session_Media

''' creating serializer class for RegisterModel with named 
RegistrationSerializer with below criteria '''


class RegistrationSerializer(serializers.ModelSerializer):
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


''' creating serializer class for RegisterModel with named EmailVerificationSerializer
'''


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = RegisterModel
        fields = ['token']


''' creating serializer class for SessionModel with named 
SessionSerializers with below criteria '''


class SessionSerializers(serializers.ModelSerializer):
    class Meta:
        model = SessionModel
        fields = ['id', 'session_id', 'date_created', 'event_name', 'event_type', 'parent_event_name', 'access_type',
                  'max_users', 'host_user_email', 'description', 'environment_id', 'category', 'content']


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
