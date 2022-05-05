from django.contrib import admin

from .models import CustomUser, EmailToken

admin.site.register(CustomUser)
admin.site.register(EmailToken)
