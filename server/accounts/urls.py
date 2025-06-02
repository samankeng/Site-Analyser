# server/accounts/urls.py - Updated with email verification and Microsoft OAuth

from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    CustomTokenObtainPairView, 
    UserRegistrationView, 
    UserProfileView,
    social_auth_token_exchange,
    disconnect_social_account,
    github_token_exchange,
    microsoft_token_exchange,  # New Microsoft endpoint
    verify_email,  # New email verification endpoint
    resend_verification_email,  # New resend verification endpoint
    request_password_reset,
    confirm_password_reset,
)

from .views import get_connected_accounts

urlpatterns = [
    # Standard auth
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    
    # Email verification
    path('verify-email/', verify_email, name='verify_email'),
    path('resend-verification/', resend_verification_email, name='resend_verification'),
    
    # Social auth
    path('social/', include('social_django.urls')),
    path('social/token/', social_auth_token_exchange, name='social_auth_token'),
    path('social/disconnect/', disconnect_social_account, name='social_disconnect'),
    path('connected-accounts/', get_connected_accounts, name='connected_accounts'),
    
    # Provider-specific OAuth endpoints
    path('github/exchange/', github_token_exchange, name='github_exchange'),
    path('microsoft/exchange/', microsoft_token_exchange, name='microsoft_exchange'),
    path('password-reset/', request_password_reset, name='password_reset'),
    path('password-reset-confirm/', confirm_password_reset, name='password_reset_confirm'),

]