from django.contrib import admin

from .models import SiteSetting,UserProfile

admin.site.register(SiteSetting)
admin.site.register(UserProfile)



