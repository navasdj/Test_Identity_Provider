from idprovider.models import User, Client, AuthReq 
from django.shortcuts import get_object_or_404
from random import *

import string
import requests

# ################################
# Check the Authorization Request.
# ################################ 
class GetAuthN:
	def GetPeticion (requestAuth,METHOD):
		if METHOD == 'GET':
			redirect_uri = requestAuth.GET.get('redirect_uri')
			client_id = requestAuth.GET.get('client_id')
			response_type = requestAuth.GET.get('response_type')
			scope = requestAuth.GET.get('scope')
			redirect_uri = requestAuth.GET.get('redirect_uri')
			state = requestAuth.GET.get('state')
			display = requestAuth.GET.get('display')
			prompt = requestAuth.GET.get('prompt')
			max_age = requestAuth.GET.get('max_age')
			ui_locales = requestAuth.GET.get('ui_locales')
			id_token_hint = requestAuth.GET.get('id_token_hint')
			login_hint = requestAuth.GET.get('login_hint')
			acr_values = requestAuth.GET.get('acr_values')
			nonce = requestAuth.GET.get('nonce')	
		else:
			redirect_uri = requestAuth.POST.get('redirect_uri')
			client_id = requestAuth.POST.get('client_id')
			response_type = requestAuth.POST.get('response_type')
			scope = requestAuth.POST.get('scope')
			redirect_uri = requestAuth.POST.get('redirect_uri')
			state = requestAuth.POST.get('state')
			display = requestAuth.POST.get('display')
			prompt = requestAuth.POST.get('prompt')
			max_age = requestAuth.POST.get('max_age')
			ui_locales = requestAuth.POST.get('ui_locales')
			id_token_hint = requestAuth.POST.get('id_token_hint')
			login_hint = requestAuth.POST.get('login_hint')
			acr_values = requestAuth.POST.get('acr_values')
			nonce = requestAuth.POST.get('nonce')
		rp = ['',''] 
		if redirect_uri == None:
			rp[0] = 'Error in Authentication Request. Not found paramater: redirect_uri.'
			return rp
		if client_id == None:
			rp[0] = 'Error in Authentication Request. Not found paramater: client_id.'
			return rp
		if response_type == None:
			rp[0] = 'Error in Authentication Request. Not found paramater: response_type.'
			return rp
		if scope == None:
			rp[0] = 'Error in Authentication Request. Not found paramater: scope.'
			return rp
		scope1 = ''
		scope2 = ''
		s1 = scope.split(" ")
		if len(s1) > 2:
			rp[0] = 'Error in Authentication Request. Parameter scope too many values.'
			return rp
		if len(s1) == 2:
			if s1.count('openid') == 1:
				scope1 = 'openid'
			else:
				rp[0] = 'Error in Authentication Request. Not found openid in scope.'
				return rp
			if s1.count('email') == 1:
				scope2 = 'email'
			else:
				rp[0] = 'Error in Authentication Request. Parameter scope only accepts: email besides openid value.'
				return rp
		elif scope != 'openid':
			rp[0] = 'Error in Authentication Request. Not found openid in scope.'
			return rp
		if len(s1) == 1:
			scope1 = scope
		if state == None:
			state = ""
		if (display != None and display != 'page'):
			rp[0] = 'Error in Authentication Request. Parameter display only accepts: page value.'
			return rp
		if (prompt != None and prompt != 'login'):
			rp[0] = 'Error in Authentication Request. Parameter prompt only accepts: login value.'
			return rp
		if max_age != None:
			try:
				max_age1 = int(max_age)
			except:
				rp[0] = 'Error in Authentication Request. Parameter max_age only accepts numbers.'
				return rp
		else:
			max_age1 = 0 		
		if (ui_locales != None and ui_locales != 'en-GB'):
			rp[0] = 'Error in Authentication Request. Parameter ui_locales only accepts: en-GB value.'
			return rp
		if (acr_values != None and acr_values != '2'):
			rp[0] = 'Error in Authentication Request. Parameter acr_values only accepts: 2 value.'
			return rp		
		if nonce == None:
			nonce = "".join(choice(NONCE_CHARSET) for x in range(randint(NONCE_MIN_CHAR, NONCE_MAX_CHAR)))

		# Create the Authentication Request. 
		AutR = AuthReq()
		AutR.clienteID = client_id
		AutR.response_type = response_type
		AutR.scope1 = scope1
		AutR.scope2 = scope2
		AutR.redirecteUri1 = redirect_uri
		AutR.state = state
		AutR.nonce = nonce
		AutR.display = display
		AutR.prompt = prompt
		AutR.max_age = max_age1
		AutR.ui_locales = ui_locales
		AutR.id_token_hint = id_token_hint
		AutR.login_hint = login_hint
		AutR.acr_values = '2'
		AutR.save()
		rp[1] = AutR.id
		return rp


# ##############################################
# Check the user/passw login from Auth. Request.
# ##############################################
class CheckAuthN:
	def Login (Email,Passw):
		user = ''
		passw = ''
		try:
			user = User.objects.get(email=Email)
		except User.DoesNotExist:
			return None
		if user.password == Passw:
			return True
		return None  

