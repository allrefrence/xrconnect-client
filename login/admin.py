from django.contrib import admin

# Register your models here.
from .models import RegisterModel


class UserAdmin(admin.ModelAdmin):
    list_display = ['user_name', 'email', ]


admin.site.register(RegisterModel, UserAdmin)
