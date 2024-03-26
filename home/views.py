from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from . serializer import UserSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from django.contrib.auth.models import User
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .serializer import LoginSerializer
from rest_framework.permissions import IsAuthenticated
import requests
from .models import HomePhoneNumber
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializer import UserSerializer
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings


class YourViewClass(APIView):
    permission_classes = [IsAuthenticated]


class UserListAPIView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        # Send email to the user upon successful signup
        user_email = serializer.validated_data['email']
        subject = 'Welcome to our platform!'

        # Load HTML template
        html_message = render_to_string('welcome.html', {'user': serializer.instance})
        plain_message = strip_tags(html_message)

        # Create email object
        email = EmailMultiAlternatives(subject, plain_message, settings.EMAIL_HOST_USER, [user_email])
        email.attach_alternative(html_message, "text/html")

        # Send email
        email.send()

        return Response(serializer.data, status=status.HTTP_201_CREATED)
# @api_view(['GET'])
# def get_username(request):
#     token = request.query_params.get('token', None)
#     if not token:
#         return Response({'error': 'Token is required'}, status=400)

#     try:
#         access_token = AccessToken(token)
#         user_id = access_token['user_id']
#         user = User.objects.get(pk=user_id)
#         username = user.username
#         return Response({'username': username})
#     except Exception as e:
#         return Response({'error': 'Invalid token'}, status=400)    
    

    
class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)



class CustomAuthToken(TokenObtainPairView):
    permission_classes = [AllowAny]  

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(request, username=username, password=password)
        if not user:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        token = self.get_token(user)

        return Response({
            'refresh': str(token),
            'access': str(token.access_token),
            'user_id': user.pk,
            'username': user.username,
        }, status=status.HTTP_200_OK)

    def get_token(self, user):
        token = super().get_token(user)

        # Check if the access token is expired
        if token.access_token_expired:
            # Generate a new refresh token
            refresh = RefreshToken.for_user(user)

            # Set the new refresh token in the response
            token['refresh'] = str(refresh)

        return token

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def get_username(request):
#     username = request.user.username
#     return Response({'username': username})






@api_view(['GET'])
@permission_classes([IsAuthenticated])
def print_user_details(request):
    try:
        # Decode the access token to get the user information
        token = request.headers.get('Authorization').split()[1]
        access_token = AccessToken(token)
        user_id = access_token.payload['user_id']
        user = User.objects.get(pk=user_id)

        # Fetch the associated phone number from the HomePhoneNumber table
        home_phone_number = HomePhoneNumber.objects.get(user=user)
        
        # Construct the user details dictionary
        user_details = {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': home_phone_number.phone_number,  # Include phone number
            # Add any other user details you want to print
        }
        
        return Response(user_details)
    except Exception as e:
        return Response({'error': str(e)}, status=400)




from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
        except Exception:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'access_token': access_token}, status=status.HTTP_200_OK)