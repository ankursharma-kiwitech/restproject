import jwt
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.urls import reverse
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import Registerserializer, EmailVerificationSerializer, Loginserializer
from .utils import Util


# Create your views here.

# Definig a class for register user
class RegisterView(generics.GenericAPIView):
    serializer_class = Registerserializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data.get("email"))
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse("verify-email")

        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
        # print(absurl)
        email_body = "Hi " + user.username + ",<br><br>Please click on the link below to verify your email " \
                                             "address.<br><br>" + absurl
        data = {
            'email_body': email_body, 'email_subject': 'Verify your email address', 'to_email': user.email,
            'message': 'Click on the link to verify your email address'}
        Util.send_email(data)
        return Response(data, status=status.HTTP_201_CREATED)


# CLASS FOR VERIFYING EMAIL ADDRESS USING TOKEN RECEIVED IN EMAIL LINK AND SETTING USER AS VERIFIED USER
class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING,
                                           description='description')

    # DECORATORS FOR VERIFYING EMAIL ADDRESS USING TOKEN RECEIVED IN EMAIL LINK AND SETTING USER AS VERIFIED USER
    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:

            payload = jwt.decode(token, settings.SECRET_KEY)

            user = User.objects.get(id=payload('user_id'))
            if not user.is_verified:
                user.is_email_verified = True
                user.save()
            return HttpResponse({'message': "Email verified successfully"}, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as identifier:
            return HttpResponse({'message': 'Token expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return HttpResponse({'message': 'Token is invalid'}, status=status.HTTP_400_BAD_REQUEST)


# CLASS FOR LOGIN USING EMAIL AND PASSWORD AND RETURNING TOKEN TO USER

class LoginView(generics.GenericAPIView):
    serializer_class = Loginserializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)
