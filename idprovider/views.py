from idprovider.models import User, Client, AuthReq, Code, token
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from IdP01.auth.authNZ import GetAuthN, CheckAuthN
from django.views.decorators.csrf import csrf_exempt
from jwt.algorithms import RSAAlgorithm
from Crypto.PublicKey import RSA
from urllib.parse import parse_qsl
from datetime import datetime, timezone
from jwkest import long_to_base64
from random import *
from idprovider.constants import *

import requests
import json
import base64
import jwt
import time

# ############################################
# Index presentation web page from IdProvider.
# ############################################
def index(request):
    return HttpResponse("Identity Provider for testing.")

# #######################################
# Manage Authorization Request from RP's.
# #######################################
def authorize(request):
	response = ['',''] 
	if request.method == 'GET':
		response = GetAuthN.GetPeticion(request,'GET')
	elif request.method == 'POST':
		response = GetAuthN.PostPeticion(request,'POST')
	if response[0] != '': 
		url_params = "?error=invalid_request_uri&error_description=" + response[0] 
		return HttpResponse(url_params)
	try:
		AuthR = AuthReq.objects.get(id=response[1])
	except  AuthReq.DoesNotExist:
		url_params = "?error=request_uri&error_description=Authentication Request internal error."
		return HttpResponse(url_params)
	return render(request, 'idprovider/authEU.html',{'AuthRID': response[1], 'ClientID': AuthR.clienteID})


# #############################################################
# Chek Authentication Request and issue a Code if successfully.
# #############################################################
def authNZ(request):
	aut = ''
	AuthRID = request.POST.get('AuthRID',False)
	AuthR = AuthReq.objects.get(id=AuthRID)
	email = request.POST.get('email',False)
	password = request.POST.get('password',False)
	aut = CheckAuthN.Login(email,password)

	if aut != True:
		url = AuthR.redirecteUri1
		AuthR.delete()
		url_params = "?error=login_required&error_description=User or password not correct."
		return HttpResponseRedirect(url + url_params)

	Codigo = "".join(choice(CODE_CHARSET) for x in range(randint(CODE_MIN_CHAR, CODE_MAX_CHAR)))
	url_params = "?scope=" + AuthR.scope1 + "&code=" + Codigo
	if AuthR.state != None:
		url_params = url_params + "&state=" + AuthR.state	

	# Create Code.
	Cod = Code()
	Cod.code = Codigo
	Cod.nonce = AuthR.nonce
	Cod.clienteID = AuthR.clienteID
	Cod.used = False
	Cod.scope = AuthR.scope1 
	Cod.auth_time = time.time()
	Cod.create_time = datetime.now(timezone.utc) 
	Cod.email = email
	Cod.save()

	return HttpResponseRedirect(AuthR.redirecteUri1 + url_params)


# ###################################################
# Get Token Request and create Token if successfully.
# ###################################################
@csrf_exempt
def accesstoken(request):
	body = dict(parse_qsl(request.body.decode('utf-8')))
	redirect_uri = body['redirect_uri']
	grant_type = body['grant_type']
	code = body['code']
	authorization = request.META.get('HTTP_AUTHORIZATION')
	
	if grant_type != 'authorization_code':
		url_params = "?error=token_validation&error_description=No authorization_code found"
		return HttpResponseRedirect(redirect_uri + url_params)

	if authorization != "":
		if authorization.find("Basic ") == -1:
			url_params = "?error=token_validation&error_description=No authorization found"
			return HttpResponseRedirect(redirect_uri + url_params)
		else:
			client = authorization.split("Basic ",1)[1]
			clientParams = base64.b64decode(client).decode('utf-8')
			if clientParams.find(":") == -1:
				url_params = "?error=token_validation&error_description=No authorization found"
				return HttpResponseRedirect(redirect_uri + url_params)
			else:
				clientName = clientParams.split(":",1)[0]
				clientSecret = clientParams.split(":",1)[1]
				try:
					Cliente = Client.objects.get(clientID=clientName)
					clientid = Cliente.clientID
				except Client.DoesNotExist:
					url_params = "?error=token_validation&error_description=No authorization found"
					return HttpResponseRedirect(redirect_uri + url_params)
				if Cliente.clientSecret != clientSecret:
					url_params = "?error=token_validation&error_description=No authorization found"
					return HttpResponseRedirect(redirect_uri + url_params)			
	else:
		url_params = "?error=token_validation&error_description=No authorization found"
		return HttpResponseRedirect(redirect_uri + url_params)
	
	try:
		Codigo = Code.objects.get(code=code)
	except Code.DoesNotExist:
		url_params = "?error=token_validation&error_description=Code invalid"
		return HttpResponseRedirect(redirect_uri + url_params)
	try:
		AuthR = AuthReq.objects.get(nonce=Codigo.nonce)
	except AuthReq.DoesNotExist:
		url_params = "?error=token_validation&error_description=Code invalid"
		return HttpResponseRedirect(redirect_uri + url_params)
	if AuthR.clienteID != clientName:
		url_params = "?error=token_validation&error_description=Code invalid"
		return HttpResponseRedirect(redirect_uri + url_params)
	if Codigo.used == True:
		url_params = "?error=token_validation&error_description=Code used"
		return HttpResponseRedirect(redirect_uri + url_params)
	
	try:
		Cliente = Client.objects.get(clientID=clientName) 
	except Client.DoesNotExist:
		url_params = "?error=token_validation&error_description=Client invalid"
		return HttpResponseRedirect(redirect_uri + url_params)	
	if ((AuthR.redirecteUri1 == Cliente.redirectUri1) or (AuthR.redirecteUri1 == Cliente.redirectUri2) or (AuthR.redirecteUri1 == Cliente.redirectUri3)) == False:
		url_params = "?error=token_validation&error_description=RedirectURI invalid"
		return HttpResponseRedirect(redirect_uri + url_params)
	
	request_time =  (datetime.now(timezone.utc) - Codigo.create_time).total_seconds()
	if request_time > CODE_EXP_TIME:
		url_params = "?error=token_validation&error_description=Code expired"
		return HttpResponseRedirect(redirect_uri + url_params)

	accessToken = "".join(choice(TOKEN_CHARSET) for x in range(randint(TOKEN_MIN_CHAR, TOKEN_MAX_CHAR)))
	refreshToken = "".join(choice(REFRESH_CHARSET) for x in range(randint(REFRESH_MIN_CHAR, REFRESH_MAX_CHAR)))
	f1 = open('/home/jn/IdP0/IdP01/idprovider/idpriv.key', 'r')
	Prikey = f1.read()
	f1.close()
	privateKey = Prikey.replace('\\n', '\n')

	iss = request.META['SERVER_NAME'] + ':' + request.META['SERVER_PORT']
	aud = clientid
	iat = time.time()
	exp = iat + TOKEN_EXP_TIME
	auth_time = Codigo.auth_time
	nonce = Codigo.nonce
	acr = "2"
	amr = ""
	azp = clientid
	try:
		user = User.objects.get(email=Codigo.email)
	except User.DoesNotExist:
        	sub = ''
	sub = user.email
	claims = {'iss': iss, 'sub': sub, 'aud': aud, 'iat': iat, 'exp': exp, 'auth_time': auth_time, 'nonce': nonce, 'acr': acr, 'azp': azp}
	tokenid = jwt.encode(claims, privateKey, algorithm='RS256')
	
	Tok = token()
	Tok.access_token = accessToken
	Tok.tokenType = 'Bearer'
	Tok.expires_in = exp	
	Tok.refresh_token = refreshToken
	Tok.id_token = tokenid.decode('utf-8')
	Tok.save()
	Codigo.used = True
	Codigo.save()
	
	response_data = {
		'access_token': accessToken,
		'token_type': 'Bearer',
		'expires_in': exp,
		'refresh_token': refreshToken,
		'id_token': tokenid.decode('utf-8')
	}	
	
	response = HttpResponse(json.dumps(response_data), content_type="application/json")
	response['Cache-Control'] = 'no-store'
	response['Pragma'] = 'no-cache'
	return response



