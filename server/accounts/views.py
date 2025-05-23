# server/accounts/views.py - Complete version with all OAuth functions

from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.conf import settings
import requests

from .serializers import (
    UserSerializer, 
    UserRegistrationSerializer, 
    CustomTokenObtainPairSerializer,
    SocialAuthTokenSerializer,
    ProfileUpdateSerializer
)
from .models import SocialAuthProfile

User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token view for JWT authentication"""
    serializer_class = CustomTokenObtainPairSerializer

class UserRegistrationView(generics.CreateAPIView):
    """Register a new user"""
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

class UserProfileView(generics.RetrieveUpdateAPIView):
    """Retrieve and update authenticated user's profile"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user
    
    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return ProfileUpdateSerializer
        return UserSerializer

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def social_auth_token_exchange(request):
    """
    Exchange social auth token for JWT tokens
    """
    serializer = SocialAuthTokenSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    provider = serializer.validated_data['provider']
    access_token = serializer.validated_data['access_token']
    
    try:
        # Verify token and get user info from provider
        if provider == 'google-oauth2':
            user_data = verify_google_token(access_token)
        elif provider == 'github':
            user_data = verify_github_token(access_token)
        else:
            return Response(
                {'error': 'Unsupported provider'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not user_data:
            return Response(
                {'error': 'Invalid token'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Find or create user
        email = user_data.get('email')
        if not email:
            return Response(
                {'error': 'Email not provided by social provider'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'first_name': user_data.get('given_name') or user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': user_data.get('family_name') or ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'is_social_account': True,
                'social_provider': provider,
                'avatar_url': user_data.get('picture') or user_data.get('avatar_url', ''),
            }
        )
        
        # Update user if not created
        if not created:
            user.merge_social_data({
                'first_name': user_data.get('given_name') or user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': user_data.get('family_name') or ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'avatar_url': user_data.get('picture') or user_data.get('avatar_url', ''),
            })
        
        # Create or update social auth profile
        social_profile, _ = SocialAuthProfile.objects.get_or_create(
            user=user,
            provider=provider,
            defaults={
                'social_id': str(user_data.get('sub') or user_data.get('id', '')),
                'access_token': access_token,
                'extra_data': user_data
            }
        )
        
        if not _:  # if not created (already existed)
            social_profile.access_token = access_token
            social_profile.extra_data = user_data
            social_profile.save()
        
        # Generate API key if not exists
        if not user.api_key:
            user.generate_api_key()
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        user_serializer = UserSerializer(user)
        
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_serializer.data
        })
        
    except Exception as e:
        return Response(
            {'error': f'Authentication failed: {str(e)}'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

def verify_google_token(access_token):
    """Verify Google OAuth2 token and return user data"""
    try:
        response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        if response.status_code == 200:
            return response.json()
    except requests.RequestException:
        pass
    return None

def verify_github_token(access_token):
    """Verify GitHub OAuth2 token and return user data"""
    try:
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        
        if user_response.status_code == 200:
            user_data = user_response.json()
            
            # Get primary email
            email_response = requests.get(
                'https://api.github.com/user/emails',
                headers={'Authorization': f'token {access_token}'}
            )
            
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next(
                    (email['email'] for email in emails if email['primary']), 
                    None
                )
                if primary_email:
                    user_data['email'] = primary_email
            
            return user_data
    except requests.RequestException:
        pass
    return None

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def disconnect_social_account(request):
    """Disconnect a social authentication account"""
    provider = request.data.get('provider')
    
    if not provider:
        return Response(
            {'error': 'Provider is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        social_profile = SocialAuthProfile.objects.get(
            user=request.user,
            provider=provider
        )
        social_profile.delete()
        
        # If this was the only auth method and user has no password, prevent disconnect
        if (request.user.is_social_account and 
            not request.user.has_usable_password() and
            not SocialAuthProfile.objects.filter(user=request.user).exists()):
            
            return Response(
                {'error': 'Cannot disconnect the only authentication method'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return Response({'message': 'Social account disconnected successfully'})
        
    except SocialAuthProfile.DoesNotExist:
        return Response(
            {'error': 'Social account not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def github_token_exchange(request):
    """
    Exchange GitHub authorization code for access token, then for JWT
    """
    code = request.data.get('code')
    state = request.data.get('state')
    
    if not code:
        return Response(
            {'error': 'Authorization code is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Exchange code for access token
        token_url = 'https://github.com/login/oauth/access_token'
        token_data = {
            'client_id': settings.SOCIAL_AUTH_GITHUB_KEY,
            'client_secret': settings.SOCIAL_AUTH_GITHUB_SECRET,
            'code': code,
            'state': state,
        }
        
        token_response = requests.post(
            token_url,
            data=token_data,
            headers={'Accept': 'application/json'}
        )
        
        if token_response.status_code != 200:
            return Response(
                {'error': 'Failed to exchange code for token'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            return Response(
                {'error': 'No access token received from GitHub'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify the token and get user data
        user_data = verify_github_token(access_token)
        
        if not user_data:
            return Response(
                {'error': 'Invalid GitHub token'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create user and generate JWT tokens (same logic as social_auth_token_exchange)
        email = user_data.get('email')
        if not email:
            return Response(
                {'error': 'Email not provided by GitHub'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'first_name': user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'is_social_account': True,
                'social_provider': 'github',
                'avatar_url': user_data.get('avatar_url', ''),
            }
        )
        
        # Update user if not created
        if not created:
            user.merge_social_data({
                'first_name': user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'avatar_url': user_data.get('avatar_url', ''),
            })
        
        # Create or update social auth profile
        social_profile, _ = SocialAuthProfile.objects.get_or_create(
            user=user,
            provider='github',
            defaults={
                'social_id': str(user_data.get('id', '')),
                'access_token': access_token,
                'extra_data': user_data
            }
        )
        
        if not _:
            social_profile.access_token = access_token
            social_profile.extra_data = user_data
            social_profile.save()
        
        # Generate API key if not exists
        if not user.api_key:
            user.generate_api_key()
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        user_serializer = UserSerializer(user)
        
        return Response({
            'success': True,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_serializer.data
        })
        
    except Exception as e:
        return Response(
            {'error': f'GitHub authentication failed: {str(e)}'}, 
            status=status.HTTP_400_BAD_REQUEST
        )