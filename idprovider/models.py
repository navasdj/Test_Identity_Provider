from django.db import models
from django import forms

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=200)
    surname = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    bird_date = models.DateTimeField('date published')
    country = models.CharField(max_length=200)
    password = models.CharField(max_length=50)
    def __str__(self):
        return self.email

class Client(models.Model):
   clientID = models.CharField(max_length=200)
   clientName = models.CharField(max_length=50) 
   clientSecret = models.CharField(max_length=50)
   redirectUri1 = models.CharField(max_length=200)
   redirectUri2 = models.CharField(max_length=200,blank=True)
   redirectUri3 = models.CharField(max_length=200,blank=True)
   OPENID = 'OP'
   PROFILE = 'PR'
   SCOPES_CHOICES = (
        (OPENID, 'openid'),
        (PROFILE, 'profile'),
    )
   scope1 = models.CharField(
        max_length=2,
        choices=SCOPES_CHOICES,
        default=OPENID,
    )
   scope2 = models.CharField(
        max_length=2,
        choices=SCOPES_CHOICES,
        blank=True
        #default=PROFILE,
    )
   def __str__(self):
        return self.clientName

class AuthReq(models.Model):
  response_type = models.CharField(max_length=20)
  scope1 = models.CharField(max_length=30)
  scope2 = models.CharField(max_length=30,null=True)
  clienteID = models.CharField(max_length=200)
  clienteName = models.CharField(max_length=50)
  clienteSecret = models.CharField(max_length=50)
  redirecteUri1 = models.CharField(max_length=200)
  state = models.CharField(max_length=200,null=True)
  nonce = models.CharField(max_length=200,null=True)
  display = models.CharField(max_length=50,null=True)
  prompt = models.CharField(max_length=50,null=True)
  max_age = models.IntegerField(default=0,null=True)
  ui_locales = models.CharField(max_length=50,null=True)
  id_token_hint = models.CharField(max_length=200,null=True)
  login_hint = models.CharField(max_length=200,null=True)
  acr_values = models.CharField(max_length=200,null=True)


class Code(models.Model):
  code = models.CharField(max_length=40)
  nonce = models.CharField(max_length=200,null=True)
  clienteID = models.CharField(max_length=200,null=True)
  scope = models.CharField(max_length=30,null=True)
  used = models.BooleanField(default=False)
  auth_time = models.CharField(max_length=40,null=True)
  create_time = models.DateTimeField('Created Date') 
  email = models.CharField(max_length=200)

class token(models.Model):
  access_token = models.CharField(max_length=100)
  token_type = models.CharField(max_length=50)
  expires_in = models.IntegerField(default=0)
  refresh_token = models.CharField(max_length=100,null=True)
  id_token = models.CharField(max_length=300)

