# creating serializers for content app and models
from rest_framework import serializers
from content.models import ContentModel, UserContentModel

''' creating serializer class for ContentModel with named 
ContentSerializers with below criteria '''


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


''' creating serializer class for UserContentModel with named 
UserContentSerializers with below criteria '''


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
