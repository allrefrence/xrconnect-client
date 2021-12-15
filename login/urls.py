"""xrconnect/login URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# declare  your URL's here..

# from  rest_framework.routers import  DefaultRouter
# router=DefaultRouter()
# router.register('Session_Users',Session_Users,basename=Session_Users)

from login import views
from django.urls import path
from .views import VerifyEmail, RegisterView, Session, SessionUsers, Media, SessionMedia, GetAllUsers, GetAllSessions, \
    GetAllMedia, GetAllSessionMedia, PasswordTokenCheckAPi, RequestPasswordResetEmail, SetNewpASSWORDApiview
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    # path('', views.index, name='index'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('signup/', RegisterView.as_view(), name='signup'),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('session/', Session.as_view(), name='session'),
    # path('sessions/',include(router.urls))
    path('session_users/', SessionUsers.as_view(), name='session_users'),
    path('media/', Media.as_view(), name='media'),
    path('session_media/', SessionMedia.as_view(), name='session_media'),
    path('all_users/', GetAllUsers.as_view(), name='all_users'),
    path('get_one_user/', views.GetOneUser.as_view(), name='one_user'),
    path('delete_user/', views.DeleteUser.as_view(), name='delete_user'),
    path('update_user/', csrf_exempt(views.UpdateUser.as_view()), name='update_user'),
    path('get_all_sessions/', GetAllSessions.as_view(), name='get_all_sessions'),
    path('get_one_session/', views.GetOneSession.as_view(), name='get_one_session'),
    path('delete_session/', views.DeleteSession.as_view(), name='delete_session'),
    path('get_all_media/', GetAllMedia.as_view(), name='get_all_media'),
    path('delete_media/', views.DeleteMedia.as_view(), name='delete_media'),
    path('get_one_session_media/', views.GetOneSessionMedia.as_view(), name='get_one_session_media'),
    path('delete_one_session_media/', views.DeleteOneSessionMedia.as_view(), name='delete_one_session_media'),
    path('all_session_media/', GetAllSessionMedia.as_view(), name='all_session_media'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('reset-password/<uidb64>/<token>/', PasswordTokenCheckAPi.as_view(), name='password-reset-confirm'),
    path('password-reset-confirm/', SetNewpASSWORDApiview.as_view(), name='password-reset-confirm')

]
