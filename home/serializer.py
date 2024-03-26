from rest_framework import serializers
from django.contrib.auth.models import User
from .models import HomePhoneNumber
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from django.core.mail import send_mail
from django.conf import settings


class HomePhoneNumberSerializer(serializers.ModelSerializer):
    class Meta:
        model = HomePhoneNumber
        fields = ['phone_number']


class UserSerializer(serializers.ModelSerializer):
    home_phone_number = HomePhoneNumberSerializer(required=False)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'home_phone_number', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        home_phone_number_data = validated_data.pop('home_phone_number', None)
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        if home_phone_number_data:
            HomePhoneNumber.objects.create(user=user, **home_phone_number_data)
        return user




class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    msg = 'User account is disabled.'
                    raise AuthenticationFailed(msg)
                return attrs
            else:
                msg = 'Unable to log in with provided credentials.'
                raise AuthenticationFailed(msg)
        else:
            msg = 'Must include "username" and "password".'
            raise AuthenticationFailed(msg)
