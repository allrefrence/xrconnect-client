# import all packages and references which are needed for business logic development  in login views
import io
import json
from datetime import timedelta
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
import jwt
from django.contrib.auth import login, authenticate
from rest_framework import status, generics, views
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.urls import reverse
from login.serializers import RegistrationSerializer, EmailVerificationSerializer, SessionSerializers, \
    SessionUserSerializers, MediaSerializers, Session_mediaSerializers, ResetPasswordEmailRequestSerializer, \
    SetNewPasswordSerializer, LoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from .models import RegisterModel
from login.models import Media as MediaModel
from login.models import SessionModel
from login.models import Session_Media as SessionMediaModel
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.permissions import AllowAny
from django.db import IntegrityError
import socket
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site

# declaring sender email address and password for sending token once users resister successfully..

sender_address = 'support@xrconnect.io'
sender_pass = 'support@!23'
socket.getaddrinfo('localhost', 8080)
if __name__ == '__main__':
    pass


# return index file

def index(request):
    return HttpResponse("Hello, world. You're at the login index.")


''' resister the users into login/register model and generate 
jwt token and send it to users email address, 
if having any errors through error message to users '''


class RegisterView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        try:
            data = request.data
            serializer = RegistrationSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                user_data = serializer.data
                user = RegisterModel.objects.get(email=user_data['email'])
                token = RefreshToken.for_user(user).access_token
                token.set_exp(lifetime=timedelta(days=36500))
                current_site = get_current_site(request).domain
                relativeLink = reverse('email-verify')
                absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
                reciver_mail = user.email
                message = MIMEMultipart()
                message['From'] = sender_address
                message['To'] = reciver_mail
                message['Subject'] = 'Registration confirmation! '
                mail_content = 'hello' + ' ' + user.user_name + ' please click this link to verify your account ' + absurl
                message.attach(MIMEText(mail_content, 'plain'))
                s = smtplib.SMTP('smtp.gmail.com', 587)
                s.starttls()
                s.login(sender_address, sender_pass)
                text = message.as_string()
                s.sendmail(sender_address, reciver_mail, text)
                s.quit()
                return Response({
                    'data': '', 'message': 'signup successful,please verify your account',
                    'code': status.HTTP_201_CREATED
                }, status=status.HTTP_201_CREATED)
            else:
                data = serializer.errors
            return Response({
                'status': 'failed', 'message': serializer.errors, 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            account = RegisterModel.objects.get(user_name='')
            account.delete()
            raise ValidationError({"400": f'{str(e)}'})
        except KeyError as e:
            print(e)
            raise ValidationError({"400": f'Field {str(e)} missing'})


# verifying the users token weather exact token or not , if not through error message...

class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        print('token=', token)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            print('-----------')
            print(payload)

            user = RegisterModel.objects.get(id=payload['user_id'])
            if not user.is_active:
                user.is_active = True
                user.save()

            return Response({'message': 'email verified successfully', 'code': status.HTTP_200_OK},
                            status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'message': 'Activation Expired', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'message': 'invalid token', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)


'''accessing users login , generating access_token and refresh_token 
if credentials was correct , else through error message '''


# @api_view(["POST", "GET"])
# @permission_classes([AllowAny])
# def login_user(request):
#     reqBody = json.loads(request.body)
#     email = reqBody['email']
#     password = reqBody['password']
#     print(email)
#
#
#
#     try:
#         print('---')
#         account = RegisterModel.objects.get(email=email, password=password)
#         print('========')
#         if account:
#             print('9999999')
#
#             if account.is_active:
#                 auth_token = RefreshToken.for_user(account).access_token
#                 login(request, account)
#                 refresh = RefreshToken.for_user(account)
#                 data = {'user_id': account.id, 'users': account.email, 'token': str(auth_token),
#                         'refresh': str(refresh), }
#                 res = {"data": data}
#                 print(res)
#                 return Response(res, status=status.HTTP_200_OK)
#
#             else:
#                 return Response({
#                     'error': 'sorry , Account not Verified'}, status=status.HTTP_400_BAD_REQUEST
#                 )
#     except RegisterModel.DoesNotExist:
#         return Response({'error': 'sorry, invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        try:
            res_serializer = LoginSerializer(data=request.data)
            if res_serializer.is_valid():
                serializer = self.serializer_class(data=request.data)
                serializer.is_valid(raise_exception=True)
                user = request.data['email']
                user_data = RegisterModel.objects.get(email=user)
                if user_data.is_active:
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response(
                        {'message': 'sorry either invalid credentials or  Account is not verified, contact admin',
                         'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST})
            else:
                return Response({
                    'status': 'failed', 'message': res_serializer.errors, 'code': status.HTTP_400_BAD_REQUEST},
                    status=status.HTTP_400_BAD_REQUEST)

        except RegisterModel.DoesNotExist:
            return Response({'message': 'invalid email', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        data = {'request': request, 'data': request.data}
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if RegisterModel.objects.filter(email=email).exists():
            user = RegisterModel.objects.get(email=email)
            reciver_mail = user.email
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = 'http://' + current_site + relativeLink
            message = MIMEMultipart()
            message['From'] = sender_address
            message['To'] = reciver_mail
            message['Subject'] = 'Reset your Password! '
            mail_content = 'hello \n  please use this link to reset your password \n ' + absurl
            message.attach(MIMEText(mail_content, 'plain'))
            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login(sender_address, sender_pass)
            text = message.as_string()
            s.sendmail(sender_address, reciver_mail, text)
            s.quit()

        return Response({'status': 'success', 'message': 'we have sent you a link to rest your password',
                         'code': status.HTTP_200_OK},
                        status=status.HTTP_200_OK)


class PasswordTokenCheckAPi(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = RegisterModel.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'status': 'failed', 'message': 'invalid token', 'code': status.HTTP_401_UNAUTHORIZED},
                                status=status.HTTP_401_UNAUTHORIZED)

            return Response(
                {'success': 'success', 'message': 'credentials valid', 'code': 'status.HTTP_200_OK', 'uidb64': uidb64,
                 'token': token},
                status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'success': 'success', 'message': 'invalid token',
                                 'code': status.HTTP_401_UNAUTHORIZED},
                                status=status.HTTP_401_UNAUTHORIZED)


class SetNewpASSWORDApiview(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': 'success', 'message': 'Password reset success', 'code': status.HTTP_200_OK},
                        status=status.HTTP_200_OK)


''' creating a session when the session data is clear , if it's 
clear create , else return error message to users '''


class Session(CreateAPIView):
    queryset = SessionModel
    serializer_class = SessionSerializers

    def create(self, request, *args, **kwargs):
        try:
            res = request.data
            session_data_serializer = SessionSerializers(data=res)
            if session_data_serializer.is_valid():
                inputF = request.data['event_name']
                day = request.data['date_created']

                all_event = str(day) + inputF

                SessionModel.objects.create(event_name=all_event, date_created=day,
                                            session_id=request.data['session_id'],
                                            event_type=request.data['event_type'],
                                            parent_event_name=request.data['parent_event_name'],
                                            access_type=request.data['access_type'],
                                            max_users=request.data['max_users'],
                                            created_by=request.data['created_by'],
                                            description=request.data['description'],
                                            environment_id=request.data['environment_id'],
                                            category=request.data['category'],
                                            content=request.data['content'])

                return Response({'message': 'session saved successfully',
                                 'status': 'success', 'code': status.HTTP_201_CREATED}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': session_data_serializer.errors,
                                 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                                status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError:
            e = 'session or event already exist with this session_id  and date '
            return Response({'message': e, 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)

    #        except IntegrityError:
    #        e = 'session or event already exist'
    #        return Response({'error': e, }, status=status.HTTP_400_BAD_REQUEST)
    #
    # except KeyError as e:
    # return Response({'message': e.args})
    #


''' creating a session_user  into sessionusermodel  when the session data is clear , if it's 
clear create , else return error message to users '''


class SessionUsers(APIView):
    def post(self, request):
        data = request.data
        serializer = SessionUserSerializers(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'sessionuser saved successfully',
                             'status': 'success', 'code': status.HTTP_201_CREATED}, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'message': serializer.errors, 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' creating a media into media model  when the session data is clear , if it's 
clear create , else return error message to users '''


class Media(APIView):
    serializer_class = MediaSerializers

    def post(self, request):
        data = request.data
        serializer_class = MediaSerializers(data=data)
        if serializer_class.is_valid():
            serializer_class.save()
            return Response({'message': 'media saved successfully',
                             'status': 'success', 'code': status.HTTP_201_CREATED}, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'message': serializer_class.errors, 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' creating a session media into sessionmediamodel  when the session media  data is clear , if it's 
clear create , else return error message to users '''


class SessionMedia(APIView):
    def post(self, request):
        data = request.data
        serializers = Session_mediaSerializers(data=data)
        if serializers.is_valid():
            serializers.save()
            return Response({'message': 'sessionmedia saved successfully',
                             'status': 'success', 'code': status.HTTP_201_CREATED}, status=status.HTTP_201_CREATED)
        else:
            return Response({
                'message': serializers.errors, 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' list all the users which are present in register model   '''


class GetAllUsers(APIView):
    def get(self, request):
        queryset = RegisterModel.objects.all()
        serializers = RegistrationSerializer(queryset, many=True)
        return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializers.data},
                        status=status.HTTP_200_OK)


''' list one users data  based on users email from registered-model   '''


class GetOneUser(APIView):
    def get(self, request):
        try:
            email = request.data['email']
            querset = RegisterModel.objects.get(email=email)
            if querset:
                serializers = RegistrationSerializer(querset)
                return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializers.data},
                                status=status.HTTP_200_OK)

        except RegisterModel.DoesNotExist:

            return Response({'message': 'invalid email', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response({'message': 'email field is required', 'status': 'failed',
                             'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)


''' delete  one users data  based on users email from registered-model   '''


class DeleteUser(APIView):
    def delete(self, request):
        email = request.data['email']
        user = RegisterModel.objects.filter(email=email).delete()
        if user[0] != 0:
            return Response({'status': 'success', 'message': 'user deleted successfully', 'code': status.HTTP_200_OK},
                            status=status.HTTP_200_OK)

        else:
            return Response({'message': 'invalid email', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)


''' update one users data  based on users email from registermodel   '''


class UpdateUser(APIView):
    def put(self, request):
        global json_data
        b_data = request.body
        streamed = io.BytesIO(b_data)
        d1 = JSONParser().parse(streamed)
        user = d1.get('email', None)
        if user:
            try:
                res = RegisterModel.objects.get(email=user)
                serializers = RegistrationSerializer(res, d1, partial=True)
                if serializers.is_valid():
                    serializers.save()
                    message = {'status': 'success', 'message': 'user updated successfully',
                               'code': status.HTTP_201_CREATED}
                    json_data = JSONRenderer().render(message
                                                      )
                    return HttpResponse(json_data, content_type='application/json', status=status.HTTP_201_CREATED)
                # else:
                #     message = {'status': 'failed', 'message': serializers.errors,
                #                'code': status.HTTP_400_BAD_REQUEST}
                #     json_data = JSONRenderer().render(message)
                #     return HttpResponse(json_data, content_type='application/json', status=status.HTTP_400_BAD_REQUEST)
            except RegisterModel.DoesNotExist:
                message = {'status': 'failed', 'message': 'invalid email',
                           'code': status.HTTP_400_BAD_REQUEST}
                json_data = JSONRenderer().render(message)
                return HttpResponse(json_data, content_type='application/json', status=status.HTTP_201_CREATED)

        else:
            message = {'status': 'failed', 'message': 'please provide email',
                       'code': status.HTTP_400_BAD_REQUEST}
            json_data = JSONRenderer().render(message)
        return HttpResponse(json_data, content_type='application/json', status=status.HTTP_201_CREATED)


''' list all sessions from session model  '''


class GetAllSessions(APIView):
    def get(self, request):
        queryset = SessionModel.objects.all()
        serializers = SessionSerializers(queryset, many=True)
        return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializers.data},
                        status=status.HTTP_200_OK)


''' list  one session data  based on session_id from   sessionmodel '''


class GetOneSession(APIView):
    def get(self, request):
        try:
            session = request.data['session_id']
            print(session)
            result = SessionModel.objects.get(session_id=session)
            if result:
                serializer = SessionSerializers(result)
                return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializer.data},
                                status=status.HTTP_200_OK)
        except SessionModel.DoesNotExist:
            return Response({'message': 'invalid session id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response(
                {'message': 'session id field is required', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' deleting  one session data  based on session_id from   sessionmodel '''


class DeleteSession(APIView):
    def delete(self, request):
        try:
            session_id = request.data['session_id']
            session = SessionModel.objects.filter(session_id=session_id).delete()
            if session[0] != 0:
                return Response(
                    {'status': 'success', 'message': 'user deleted successfully', 'code': status.HTTP_200_OK},
                    status=status.HTTP_200_OK)

            else:
                return Response(
                    {'message': 'invalid session id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                    status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response(
                {'message': 'session id field is required', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' list  all media data based on media_id from media model '''


class GetAllMedia(APIView):
    def get(self, request):
        queryset = MediaModel.objects.all()
        serializers = MediaSerializers(queryset, many=True)
        return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializers.data},
                        status=status.HTTP_200_OK)


''' delete  one media  data  based  on media_id from   metamodel '''


class DeleteMedia(APIView):
    def delete(self, request):
        try:
            media_id = request.data['media_id']
            queryset = MediaModel.objects.filter(media_id=media_id).delete()
            if queryset[0] != 0:
                return Response(
                    {'status': 'success', 'message': 'media deleted successfully', 'code': status.HTTP_200_OK},
                    status=status.HTTP_200_OK)

            else:
                return Response(
                    {'message': 'invalid media id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                    status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response(
                {'message': 'media id field is required', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' list  all session_media data records    from   sessionmediamodel '''


class GetAllSessionMedia(APIView):
    def get(self, request):
        queryset = SessionMediaModel.objects.all()
        serializers = Session_mediaSerializers(queryset, many=True)
        return Response({'status': 'success', 'code': status.HTTP_200_OK, 'data': serializers.data},
                        status=status.HTTP_200_OK)


''' list  one session_media data  based  on session_id from   sessionmediamodel '''


class GetOneSessionMedia(APIView):
    def get(self, request):
        try:
            session_id = request.data['session_id']
            res = SessionMediaModel.objects.get(session_id=session_id)
            if res:
                dta = Session_mediaSerializers(res)
                return Response({'status': 'success', 'code': status.HTTP_200_OK, 'session': dta.data},
                                status=status.HTTP_200_OK)
            else:
                return Response(
                    {'message': 'invalid session id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                    status=status.HTTP_400_BAD_REQUEST)
        except SessionMediaModel.DoesNotExist:
            return Response({'message': 'invalid session id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                            status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response(
                {'message': 'session id field is required', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)


''' delete  one session_media data  based session_id from   sessionmediamodel '''


class DeleteOneSessionMedia(APIView):
    def delete(self, request):
        try:

            session_id = request.data['session_id']
            res = SessionMediaModel.objects.filter(session_id=session_id).delete()
            if res[0] != 0:
                return Response(
                    {'status': 'success', 'message': 'media deleted successfully', 'code': status.HTTP_200_OK},
                    status=status.HTTP_200_OK)
            else:
                return Response(
                    {'message': 'invalid session id', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                    status=status.HTTP_400_BAD_REQUEST)
        except KeyError:
            return Response(
                {'message': 'session id field is required', 'status': 'failed', 'code': status.HTTP_400_BAD_REQUEST},
                status=status.HTTP_400_BAD_REQUEST)
