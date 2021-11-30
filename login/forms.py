from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
#from .models import UsersModel


class CustomUserCreationForm(UserCreationForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        #model = UsersModel
        fields = ('email', 'username', 'password', 'gender', 'is_active', 'login_status', 'company_name')


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        #model = UsersModel
        fields = UserChangeForm.Meta.fields
