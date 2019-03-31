from django.contrib import admin

# Register your models here.
from .models import User, Client, AuthReq, Code

admin.site.register(User)
admin.site.register(Client)
admin.site.register(AuthReq)
admin.site.register(Code)
