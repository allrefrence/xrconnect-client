from rest_framework import serializers
from content.models import ContentModel, UserContentModel


class ContentSerializers(serializers.ModelSerializer):
    class Meta:
        model = ContentModel
        fields = [
            'content_id',
            'content_name',
            'content_type',
            'thumbnail_path',
            'description',
            'owner',
            'access_type',
            'file_path',
            'file_name',
            'version',
            'buildtarget'
        ]


class UserContentSerializers(serializers.ModelSerializer):
    class Meta:
        model = UserContentModel
        fields = [
            'content_id',
            'content_name',
            'content_type',
            'content_load_type',
            'thumbnail_path',
            'description',
            'owner',
            'access_type',
            'path',
            'version',
            'file_name',
            'build_target'
        ]
