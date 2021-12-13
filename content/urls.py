"""xrconnect/content URL Configuration

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

from django.contrib import admin
from django.urls import path, include

from content import views

urlpatterns = [
    path('content/', views.Content.as_view(), name='content'),
    path('get_all_content/', views.Get_All_Content.as_view(), name='get_all_content'),
    path('get_buildtarget_content/', views.Get_Buildtarget_Content.as_view(), name='get_buildtarget_content'),
    path('get_one_content/', views.Get_One_Content.as_view(), name='get_one_content'),
    path('user_content/', views.UserContent.as_view(), name='user_content'),
    path('get_all_user_contents/', views.GetAllUserContents.as_view(), name='get_all_user_contents'),
    path('get_usercontent_buildtarget/', views.GetUserBuildtargetContent.as_view(), name='get_usercontent_buildtarget'),
    path('get_one_usercontent/', views.GetOneUserContent.as_view(), name='get_one_usercontent'),
    path('get_environment_data/', views.GetEnvironmentData.as_view(), name='get_environment_data'),
    path('get_application_data/', views.GetApplicationData.as_view(), name='get_application_data'),

]
