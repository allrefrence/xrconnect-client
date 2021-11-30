from rest_framework import serializers
from .models import RegisterModel, SessionModel, Session_Users, Media, Session_Media


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
            #"is_social_user"
        )

        extra_kwargs = {"password_hash": {"write_only": True}}


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = RegisterModel
        fields = ['token']


class SessionSerializers(serializers.ModelSerializer):
    class Meta:
        model = SessionModel
        fields = ['id', 'session_id', 'date_created', 'event_name', 'event_type', 'parent_event_name', 'access_type',
                  'max_users', 'host_user_email', 'description', 'environment_id', 'category', 'content']


class SessionUserSerializers(serializers.ModelSerializer):
    class Meta:
        model = Session_Users
        fields = "__all__"


class MediaSerializers(serializers.ModelSerializer):
    class Meta:
        model = Media
        fields = ['media_id', 'media_type', 'thumbnail_path', 'description', 'owner', 'upload_by', 'access_type',
                  'permitted_users', 'path', 'version']


class Session_mediaSerializers(serializers.ModelSerializer):
    class Meta:
        model = Session_Media
        fields = "__all__"
