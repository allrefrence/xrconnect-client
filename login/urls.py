from login import views
from django.urls import path

from .views import VerifyEmail, RegisterView, Session, SessionUsers, Media, SessionMedia, GetAllUsers, GetAllSessions, \
    GetAllMedia
from django.views.decorators.csrf import csrf_exempt

# from  rest_framework.routers import  DefaultRouter
# router=DefaultRouter()
# router.register('Session_Users',Session_Users,basename=Session_Users)


urlpatterns = [
    # path('', views.index, name='index'),
    path('login/', views.login_user, name='login'),
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


]
