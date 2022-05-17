from django.contrib import auth
from rest_framework import serializers
from .models import User

from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']


    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError('Username must be alphanumeric')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):  # Serializer for email verification
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=60, min_length=6, write_only=True)

    username = serializers.CharField(max_length=255, min_length=4, read_only=True)

    is_superuser = serializers.BooleanField(read_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self):
        user = User.objects.get(email=self['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens'] + ['is_superuser']



    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        # if filtered_user_by_email.exists() and 'email' != filtered_user_by_email[0].auth_provider:
        #     raise AuthenticationFailed(
        #         detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)

        if not user:
            raise AuthenticationFailed('Invalid credentials')

        if not user.is_active:
            raise AuthenticationFailed('account is not active  please re-activate your account')

        if not user.is_verified:
            raise AuthenticationFailed('User is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'is_superuser': user.is_superuser,
            'tokens': user.tokens()

        }


