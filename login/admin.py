from django.contrib import admin
from login.models import RegisterModel, SessionModel, Session_Users, Session_Media, Media

admin.site.register(RegisterModel)
admin.site.register(Session_Media)
admin.site.register(SessionModel)
admin.site.register(Session_Users)
admin.site.register(Media)
