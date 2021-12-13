# import all packages and references which are needed for business logic development  in content  views
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from content.models import ContentModel, UserContentModel
from content.serializers import ContentSerializers, UserContentSerializers

# create your views from here
''' creating a content record  into Contentmodel   when the content  data is clear , if it's 
clear create , else return error message to user '''


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


''' list all the Get_All_Content which are present in ContentModel model   '''


class Get_All_Content(APIView):
    def get(self, request):
        data = ContentModel.objects.all()
        serializers_class = ContentSerializers(data, many=True)
        return Response(serializers_class.data, status=status.HTTP_200_OK)


''' list   one buildtarget data  based on buildtarget and content_id from ContentModel   '''


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


''' list  one Content record  based on content_id from   ContentModel '''


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


''' creating a UserContent record  into UserContent   when the content  data is clear , if it's 
clear create , else return error message to user '''


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


''' list all the GetAllUserContents which are present in UserContentModel model   '''


class GetAllUserContents(APIView):
    def get(self, request):
        data = UserContentModel.objects.all()
        responce = UserContentSerializers(data, many=True)
        return Response(responce.data, status=status.HTTP_200_OK)


''' list   one build_target data  based on build_target and content_id from UserContentModel   '''


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


''' list   OneUserContent record  based on content_id from   UserContentModel '''


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


''' list   EnvironmentData record    ContentModel '''


class GetEnvironmentData(APIView):
    def get(self, request):
        data = ContentModel.objects.filter(content_type=2)
        response = ContentSerializers(data, many=True)
        return Response(response.data, status=status.HTTP_200_OK)


''' list   ApplicationData record    ContentModel '''


class GetApplicationData(APIView):
    def get(self, request):
        resp = ContentModel.objects.filter(content_type=1)
        response = ContentSerializers(resp, many=True)
        return Response(response.data, status=status.HTTP_200_OK)
