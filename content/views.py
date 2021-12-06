from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from content.models import ContentModel, UserContentModel
from content.serializers import ContentSerializers, UserContentSerializers


class Content(APIView):
    def post(self, request):
        data = request.data
        serilaizers_class = ContentSerializers(data=data)
        if serilaizers_class.is_valid():
            serilaizers_class.save()
            return Response({'success': 'content saved', 'message': serilaizers_class.data},
                            status=status.HTTP_201_CREATED)
        else:
            errors = {'error': serilaizers_class.errors}
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)


class Get_All_Content(APIView):
    def get(self, request):
        data = ContentModel.objects.all()
        serializers_class = ContentSerializers(data, many=True)
        return Response(serializers_class.data, status=status.HTTP_200_OK)


class Get_Buildtarget_Content(APIView):
    def get(self, request):
        try:
            data = request.data['buildtarget']
            content = request.data['content_id']
            print(data)
            res = ContentModel.objects.filter(buildtarget=data, content_id=content)
            if res:
                serializers = ContentSerializers(res, many=True)
                return Response(serializers.data, status=status.HTTP_200_OK)
            else:
                error = {'error': 'sorry, no content data with this build-target and content_id request '}
            return Response(error, status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response({'error': 'sorry, content_id and build_target both is required'},
                            status=status.HTTP_400_BAD_REQUEST)


class Get_One_Content(APIView):
    def get(self, request):
        try:
            content = request.data['content_id']

            print(content)
            res = ContentModel.objects.get(content_id=content)
            if res:
                response = ContentSerializers(res)
                return Response(response.data, status=status.HTTP_200_OK)

        except ContentModel.DoesNotExist:
            return Response({'error': 'sorry no content is available with this content_id'},
                            status=status.HTTP_400_BAD_REQUEST)


class UserContent(APIView):
    def post(self, request):
        data = request.data
        serializers_class = UserContentSerializers(data=data)

        if serializers_class.is_valid():
            serializers_class.save()
            return Response({'message': 'content for user is saved', 'response': serializers_class.data},
                            status=status.HTTP_201_CREATED)
        else:
            return Response({'errors': serializers_class.errors}, status=status.HTTP_400_BAD_REQUEST)


class GetAllUserContents(APIView):
    def get(self, request):
        data = UserContentModel.objects.all()
        responce = UserContentSerializers(data, many=True)
        return Response(responce.data, status=status.HTTP_200_OK)


class GetUserBuildtargetContent(APIView):
    def get(self, request):
        try:
            content = request.data['content_id']
            buildtarget = request.data['build_target']
            data = UserContentModel.objects.filter(content_id=content, build_target=buildtarget)
            if data:
                serializers = UserContentSerializers(data, many=True)
                return Response(serializers.data, status=status.HTTP_200_OK)
            else:
                error = {'error': 'sorry, no user content data with this build_target and content_id  request '}
            return Response(error, status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response({'error': 'sorry, content_id and build_target both is required'},
                            status=status.HTTP_400_BAD_REQUEST)


class GetOneUserContent(APIView):
    def get(self, request):
        contid = request.data['content_id']
        resp = UserContentModel.objects.filter(content_id=contid)
        if resp:
            data = UserContentSerializers(resp, many=True)
            return Response(data.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'sorry, no user content with this content_id'},
                            status=status.HTTP_400_BAD_REQUEST)


class GetEnvironmentData(APIView):
    def get(self, request):
        data = ContentModel.objects.filter(content_type=2)
        response = ContentSerializers(data, many=True)
        return Response(response.data, status=status.HTTP_200_OK)


class GetApplicationData(APIView):
    def get(self, request):
        resp = ContentModel.objects.filter(content_type=1)
        response = ContentSerializers(resp, many=True)
        return Response(response.data, status=status.HTTP_200_OK)
