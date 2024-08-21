from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from rest_framework.exceptions import AuthenticationFailed

import jwt
import datetime
from .models import User
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
# Create your views here.

class registerAPIView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)   #if anything not valid, raise exception
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Mot de passe'),
            }
        ),
        responses={
            200: openapi.Response('Connexion réussie'),
            400: openapi.Response('User not found or Invalid password'),
        }
    )
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        #find user using email
        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found:)')
            
        if not user.check_password(password):
            raise AuthenticationFailed('Invalid password')

       
        payload = {
            "id": user.id,
            "email": user.email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            "iat": datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')
        # token.decode('utf-8')
        #we set token via cookies
        

        response = Response() 

        response.set_cookie(key='jwt', value=token, httponly=True)  #httonly - frontend can't access cookie, only for backend

        response.data = {
            'jwt token': token,
            'email': user.email,
            'username' : user.name
        }

        #if password correct
        return response


# get user using cookie
class UserView(APIView):
    @swagger_auto_schema(
        responses={
            200: UserSerializer(),
            401: openapi.Response('Unauthorized'),
        }
    )
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed("Unauthenticated!")
        
        try:
            payload = jwt.decode(token, 'secret', algorithms="HS256")
            #decode gets the user

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated!")
        
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)
        #cookies accessed if preserved

class LogoutView(APIView):
    @swagger_auto_schema(responses={200: 'Déconnexion réussie'})
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'successful'
        }

        return response
    

    """
    from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer
from .models import User
import jwt
import datetime
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class UserView(APIView):
    @swagger_auto_schema(
        responses={
            200: UserSerializer(),
            401: openapi.Response('Unauthorized'),
        }
    )
    def get(self, request):
        # Récupérer le token du header Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthenticationFailed("Authorization header is missing!")

        # Le format attendu est "Bearer <token>"
        try:
            prefix, token = auth_header.split(' ')
            if prefix.lower() != 'bearer':
                raise AuthenticationFailed("Invalid token prefix. Use 'Bearer'.")
        except ValueError:
            raise AuthenticationFailed("Invalid Authorization header format. Use 'Bearer <token>'.")

        try:
            payload = jwt.decode(token, 'secret', algorithms="HS256")
            # Décoder pour obtenir l'utilisateur
            user = User.objects.filter(id=payload['id']).first()
            if user is None:
                raise AuthenticationFailed("User not found.")
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        
        serializer = UserSerializer(user)
        return Response(serializer.data)


    """