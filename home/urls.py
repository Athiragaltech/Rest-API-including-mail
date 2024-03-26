from django.urls import path
from .views import UserListAPIView
from django.urls import path


from .views import print_user_details,CustomTokenObtainPairView,CustomAuthToken,RefreshTokenView


urlpatterns = [
    path('signup/', UserListAPIView.as_view(), name='signup'),

    path('api/token/refresh/', RefreshTokenView.as_view(), name='refresh_token'),
    path('api/print-user-details/', print_user_details, name='print_user_details'),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/hi', CustomAuthToken.as_view(), name='custom_token_obtain_pair'),
]
