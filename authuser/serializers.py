from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed


class Registerserializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=60, min_length=6, style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']
        extra_kwargs = {'password': {'write_only': True}}

        def validate(self, attrs):
            email = attrs.get('email', '')
            username = attrs.get('username', '')
            password = attrs.get('password', '')

            if not username.isalnum():
                raise serializers.ValidationError('Username must be alphanumeric')
            return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):  # Serializer for email verification
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'token']


class Loginserializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=4, write_only=True)
    password = serializers.CharField(max_length=60, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=4, read_only=True)
    token = serializers.CharField(max_length=255, read_only=True)
    is_superuser = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'token', 'username'] + ['is_superuser']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials')

        if not user.is_verified:
            raise AuthenticationFailed('User is not verified')

        if not user.is_active:
            raise AuthenticationFailed('account is not active  please re-activate your account')

        return {
            'email': user.email,
            'username': user.username,
            'token': user.token(),
            'message': 'Logged in successfully'
        }

        return super().validate(attrs)
