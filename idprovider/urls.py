from django.urls import path

from . import views

app_name = 'idprovider'
urlpatterns = [
    path('', views.index, name='index'),
    path('authorize/', views.authorize, name='authorize'),
    path('authNZ/', views.authNZ, name='authNZ'),
    path('access_token/', views.accesstoken, name='accesstoken'),
]
