# server/accounts/urls.py - Updated to include GitHub exchange

from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    CustomTokenObtainPairView, 
    UserRegistrationView, 
    UserProfileView,
    social_auth_token_exchange,
    disconnect_social_account,
    github_token_exchange  # Add this import
)

urlpatterns = [
    # Standard auth
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    
    # Social auth
    path('social/', include('social_django.urls', namespace='social')),
    path('social/token/', social_auth_token_exchange, name='social_auth_token'),
    path('social/disconnect/', disconnect_social_account, name='social_disconnect'),
    
    # GitHub specific endpoint
    path('github/exchange/', github_token_exchange, name='github_exchange'),
]

