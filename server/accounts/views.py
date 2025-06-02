# server/accounts/views.py - Enhanced with email verification and Microsoft OAuth

import logging
from rest_framework import generics, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.utils import timezone
import requests

from .serializers import (
    UserSerializer, 
    UserRegistrationSerializer, 
    CustomTokenObtainPairSerializer,
    SocialAuthTokenSerializer,
    ProfileUpdateSerializer
)
from .models import SocialAuthProfile, EmailVerificationAttempt

logger = logging.getLogger(__name__)
User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token view for JWT authentication"""
    serializer_class = CustomTokenObtainPairSerializer

class UserRegistrationView(generics.CreateAPIView):
    """Register a new user with email verification"""
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        # Add debugging
        logger.info(f"Registration attempt with data: {request.data}")
        
        serializer = self.get_serializer(data=request.data)
        
        # Check if serializer is valid and log errors if not
        if not serializer.is_valid():
            logger.error(f"Registration validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = serializer.save()
            logger.info(f"User created successfully: {user.email}")
            
            # Send verification email for regular registrations
            if not user.is_social_account:
                try:
                    send_verification_email(user)
                    logger.info(f"Verification email sent to {user.email}")
                except Exception as e:
                    logger.error(f"Failed to send verification email: {str(e)}")
                    # Don't fail registration if email fails - user can resend later
            
            return Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'email': user.email,
                'requires_verification': not user.is_email_verified
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Registration failed: {str(e)}")
            return Response(
                {'error': 'Registration failed. Please try again.'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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

def send_verification_email(user):
    """Send email verification email to user"""
    try:
        # Check if we can send verification email
        attempt, created = EmailVerificationAttempt.objects.get_or_create(email=user.email)
        
        if not attempt.can_send_verification():
            raise Exception("Too many verification attempts. Please try again later.")
        
        # Generate verification token
        token = user.generate_email_verification_token()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Create verification URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        verification_url = f"{frontend_url}/auth/verify-email?token={token}&uid={uid}"
        
        # Prepare email content
        context = {
            'user': user,
            'verification_url': verification_url,
            'site_name': 'Site Analyser',
        }
        
        subject = 'Verify your email address - Site Analyser'
        
        try:
            html_message = render_to_string('emails/email_verification.html', context)
            plain_message = render_to_string('emails/email_verification.txt', context)
        except Exception as template_error:
            logger.error(f"Template rendering failed: {str(template_error)}")
            # Fallback to simple text email
            plain_message = f"""
Hi {user.get_full_name()},

Thank you for signing up for Site Analyser! 

Please verify your email address by clicking this link:
{verification_url}

This link will expire in 24 hours.

Thanks,
The Site Analyser Team
            """.strip()
            html_message = None
        
        # Send email
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@siteanalyser.com')
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=from_email,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        # Record the attempt
        attempt.record_attempt()
        
        logger.info(f"Verification email sent to {user.email}")
        
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        raise

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    """Verify user email with token"""
    token = request.data.get('token')
    uid = request.data.get('uid')
    
    if not token or not uid:
        return Response(
            {'error': 'Token and UID are required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
        
        # Check if token is valid and not expired
        if (user.email_verification_token != token or 
            user.is_email_verification_expired()):
            return Response(
                {'error': 'Invalid or expired verification link'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify the email
        user.verify_email()
        
        return Response({'message': 'Email verified successfully'})
        
    except (User.DoesNotExist, ValueError):
        return Response(
            {'error': 'Invalid verification link'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def resend_verification_email(request):
    """Resend verification email"""
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)
        
        if user.is_email_verified:
            return Response(
                {'error': 'Email is already verified'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        send_verification_email(user)
        
        return Response({'message': 'Verification email sent successfully'})
        
    except User.DoesNotExist:
        return Response(
            {'error': 'User with this email does not exist'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def social_auth_token_exchange(request):
    """Exchange social auth token for JWT tokens"""
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
        elif provider == 'microsoft':
            user_data = verify_microsoft_token(access_token)
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
                'is_email_verified': True,  # Social accounts are considered verified
            }
        )
        
        # Update user if not created
        if not created and hasattr(user, 'merge_social_data'):
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
        if not user.api_key and hasattr(user, 'generate_api_key'):
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
        logger.error(f'Social auth error: {str(e)}')
        return Response(
            {'error': f'Authentication failed: {str(e)}'}, 
            status=status.HTTP_400_BAD_REQUEST
        )

def verify_google_token(access_token):
    """Verify Google OAuth2 token and return user data"""
    try:
        response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        logger.error(f'Google token verification error: {str(e)}')
    return None

def verify_github_token(access_token):
    """Verify GitHub OAuth2 token and return user data"""
    try:
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={
                'Authorization': f'token {access_token}',
                'User-Agent': 'Site-Analyser-App'
            },
            timeout=10
        )
        
        if user_response.status_code == 200:
            user_data = user_response.json()
            
            # Get primary email if not public
            if not user_data.get('email'):
                email_response = requests.get(
                    'https://api.github.com/user/emails',
                    headers={
                        'Authorization': f'token {access_token}',
                        'User-Agent': 'Site-Analyser-App'
                    },
                    timeout=10
                )
                
                if email_response.status_code == 200:
                    emails = email_response.json()
                    primary_email = next(
                        (email['email'] for email in emails if email.get('primary')), 
                        None
                    )
                    if primary_email:
                        user_data['email'] = primary_email
            
            return user_data
    except requests.RequestException as e:
        logger.error(f'GitHub token verification error: {str(e)}')
    return None

def verify_microsoft_token(access_token):
    """Verify Microsoft OAuth2 token and return user data"""
    try:
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=10
        )
        if response.status_code == 200:
            user_data = response.json()
            # Microsoft Graph API returns different field names
            return {
                'id': user_data.get('id'),
                'email': user_data.get('mail') or user_data.get('userPrincipalName'),
                'given_name': user_data.get('givenName'),
                'family_name': user_data.get('surname'),
                'name': user_data.get('displayName'),
                'picture': None,  # Would need additional permission for profile photo
            }
    except requests.RequestException as e:
        logger.error(f'Microsoft token verification error: {str(e)}')
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
        
        # Check if this was the only auth method
        remaining_profiles = SocialAuthProfile.objects.filter(user=request.user).count()
        has_password = request.user.has_usable_password()
        
        if remaining_profiles == 0 and not has_password:
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
    """Exchange GitHub authorization code for access token, then for JWT"""
    logger.info("GitHub OAuth exchange initiated")
    
    code = request.data.get('code')
    state = request.data.get('state')
    
    if not code:
        logger.error("No authorization code provided")
        return Response(
            {'error': 'Authorization code is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Use the correct settings attributes
    github_client_id = getattr(settings, 'GITHUB_KEY', None)
    github_client_secret = getattr(settings, 'GITHUB_SECRET', None)
    
    logger.info(f"GitHub credentials configured: ID={'YES' if github_client_id else 'NO'}, Secret={'YES' if github_client_secret else 'NO'}")
    
    if not github_client_id or not github_client_secret:
        logger.error("GitHub OAuth credentials not configured")
        return Response(
            {'error': 'GitHub OAuth not configured on server'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    try:
        # Exchange code for access token
        logger.info("Exchanging code for access token")
        token_url = 'https://github.com/login/oauth/access_token'
        token_data = {
            'client_id': github_client_id,
            'client_secret': github_client_secret,
            'code': code,
        }
        
        if state:
            token_data['state'] = state
        
        token_response = requests.post(
            token_url,
            data=token_data,
            headers={'Accept': 'application/json'},
            timeout=10
        )
        
        logger.info(f"GitHub token response status: {token_response.status_code}")
        
        if token_response.status_code != 200:
            logger.error(f"GitHub token exchange failed: {token_response.text}")
            return Response(
                {'error': f'Failed to exchange code for token: {token_response.status_code}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        token_data = token_response.json()
        logger.info(f"Token response keys: {list(token_data.keys())}")
        
        access_token = token_data.get('access_token')
        error = token_data.get('error')
        error_description = token_data.get('error_description')
        
        if error:
            logger.error(f"GitHub OAuth error: {error} - {error_description}")
            return Response(
                {'error': f'GitHub OAuth error: {error}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not access_token:
            logger.error(f"No access token in response: {token_data}")
            return Response(
                {'error': 'No access token received from GitHub'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get user data from GitHub
        logger.info("Getting user data from GitHub")
        user_data = verify_github_token(access_token)
        
        if not user_data:
            logger.error("Failed to get user data from GitHub")
            return Response(
                {'error': 'Failed to get user data from GitHub'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create user and generate JWT tokens
        email = user_data.get('email')
        if not email:
            logger.error("No email provided by GitHub")
            return Response(
                {'error': 'Email not provided by GitHub. Please make your GitHub email public.'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(f"Creating/getting user with email: {email}")
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': user_data.get('login', email),
                'first_name': user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'is_social_account': True,
                'social_provider': 'github',
                'avatar_url': user_data.get('avatar_url', ''),
                'is_email_verified': True,  # GitHub accounts are considered verified
            }
        )
        
        logger.info(f"User {'created' if created else 'found'}: {user.email}")
        
        # Update user if not created
        if not created and hasattr(user, 'merge_social_data'):
            user.merge_social_data({
                'first_name': user_data.get('name', '').split(' ')[0] if user_data.get('name') else '',
                'last_name': ' '.join(user_data.get('name', '').split(' ')[1:]) if user_data.get('name') else '',
                'avatar_url': user_data.get('avatar_url', ''),
            })
        
        # Create or update social auth profile
        social_profile, profile_created = SocialAuthProfile.objects.get_or_create(
            user=user,
            provider='github',
            defaults={
                'social_id': str(user_data.get('id', '')),
                'access_token': access_token,
                'extra_data': user_data
            }
        )
        
        if not profile_created:
            social_profile.access_token = access_token
            social_profile.extra_data = user_data
            social_profile.save()
        
        logger.info(f"Social profile {'created' if profile_created else 'updated'}")
        
        # Generate API key if not exists
        if not user.api_key and hasattr(user, 'generate_api_key'):
            user.generate_api_key()
            logger.info("Generated API key for user")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        user_serializer = UserSerializer(user)
        
        logger.info("JWT tokens generated successfully")
        
        return Response({
            'success': True,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_serializer.data
        })
        
    except requests.RequestException as e:
        logger.error(f"Network error during GitHub OAuth: {str(e)}")
        return Response(
            {'error': f'Network error: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    except Exception as e:
        logger.error(f"Unexpected error during GitHub OAuth: {str(e)}")
        return Response(
            {'error': f'GitHub authentication failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def microsoft_token_exchange(request):
    """Exchange Microsoft authorization code for access token, then for JWT"""
    logger.info("Microsoft OAuth exchange initiated")
    
    code = request.data.get('code')
    state = request.data.get('state')
    
    if not code:
        logger.error("No authorization code provided")
        return Response(
            {'error': 'Authorization code is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Use the correct settings attributes
    microsoft_client_id = getattr(settings, 'MICROSOFT_CLIENT_ID', None)
    microsoft_client_secret = getattr(settings, 'MICROSOFT_CLIENT_SECRET', None)
    
    logger.info(f"Microsoft credentials configured: ID={'YES' if microsoft_client_id else 'NO'}, Secret={'YES' if microsoft_client_secret else 'NO'}")
    
    if not microsoft_client_id or not microsoft_client_secret:
        logger.error("Microsoft OAuth credentials not configured")
        return Response(
            {'error': 'Microsoft OAuth not configured on server'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    try:
        # Exchange code for access token
        logger.info("Exchanging code for access token")
        token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        redirect_uri = f"{settings.FRONTEND_URL}/auth/microsoft/callback"
        
        token_data = {
            'client_id': microsoft_client_id,
            'client_secret': microsoft_client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }
        
        if state:
            token_data['state'] = state
        
        token_response = requests.post(
            token_url,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        
        logger.info(f"Microsoft token response status: {token_response.status_code}")
        
        if token_response.status_code != 200:
            logger.error(f"Microsoft token exchange failed: {token_response.text}")
            return Response(
                {'error': f'Failed to exchange code for token: {token_response.status_code}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        token_data = token_response.json()
        logger.info(f"Token response keys: {list(token_data.keys())}")
        
        access_token = token_data.get('access_token')
        error = token_data.get('error')
        error_description = token_data.get('error_description')
        
        if error:
            logger.error(f"Microsoft OAuth error: {error} - {error_description}")
            return Response(
                {'error': f'Microsoft OAuth error: {error}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not access_token:
            logger.error(f"No access token in response: {token_data}")
            return Response(
                {'error': 'No access token received from Microsoft'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get user data from Microsoft
        logger.info("Getting user data from Microsoft")
        user_data = verify_microsoft_token(access_token)
        
        if not user_data:
            logger.error("Failed to get user data from Microsoft")
            return Response(
                {'error': 'Failed to get user data from Microsoft'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create user and generate JWT tokens
        email = user_data.get('email')
        if not email:
            logger.error("No email provided by Microsoft")
            return Response(
                {'error': 'Email not provided by Microsoft'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(f"Creating/getting user with email: {email}")
        
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'first_name': user_data.get('given_name', ''),
                'last_name': user_data.get('family_name', ''),
                'is_social_account': True,
                'social_provider': 'microsoft',
                'is_email_verified': True,  # Microsoft accounts are considered verified
            }
        )
        
        logger.info(f"User {'created' if created else 'found'}: {user.email}")
        
        # Update user if not created
        if not created and hasattr(user, 'merge_social_data'):
            user.merge_social_data({
                'first_name': user_data.get('given_name', ''),
                'last_name': user_data.get('family_name', ''),
            })
        
        # Create or update social auth profile
        social_profile, profile_created = SocialAuthProfile.objects.get_or_create(
            user=user,
            provider='microsoft',
            defaults={
                'social_id': str(user_data.get('id', '')),
                'access_token': access_token,
                'extra_data': user_data
            }
        )
        
        if not profile_created:
            social_profile.access_token = access_token
            social_profile.extra_data = user_data
            social_profile.save()
        
        logger.info(f"Social profile {'created' if profile_created else 'updated'}")
        
        # Generate API key if not exists
        if not user.api_key and hasattr(user, 'generate_api_key'):
            user.generate_api_key()
            logger.info("Generated API key for user")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        user_serializer = UserSerializer(user)
        
        logger.info("JWT tokens generated successfully")
        
        return Response({
            'success': True,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': user_serializer.data
        })
        
    except requests.RequestException as e:
        logger.error(f"Network error during Microsoft OAuth: {str(e)}")
        return Response(
            {'error': f'Network error: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    except Exception as e:
        logger.error(f"Unexpected error during Microsoft OAuth: {str(e)}")
        return Response(
            {'error': f'Microsoft authentication failed: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
# Add these views to your server/accounts/views.py file

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def request_password_reset(request):
    """Request password reset email"""
    email = request.data.get('email')
    
    if not email:
        return Response(
            {'error': 'Email is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        user = User.objects.get(email=email)
        
        # Generate password reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        # Create reset URL
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        reset_url = f"{frontend_url}/auth/reset-password?token={token}&uid={uid}"
        
        # Prepare email content
        context = {
            'user': user,
            'reset_url': reset_url,
            'site_name': 'Site Analyser',
        }
        
        subject = 'Reset your password - Site Analyser'
        
        try:
            html_message = render_to_string('emails/password_reset.html', context)
            plain_message = render_to_string('emails/password_reset.txt', context)
        except Exception as template_error:
            logger.error(f"Template rendering failed: {str(template_error)}")
            # Fallback to simple text email
            plain_message = f"""
Hi {user.get_full_name()},

You requested a password reset for your Site Analyser account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, please ignore this email.

Thanks,
The Site Analyser Team
            """.strip()
            html_message = None
        
        # Send email
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@siteanalyser.com')
        
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=from_email,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Password reset email sent to {user.email}")
        
        return Response({'message': 'Password reset email sent successfully'})
        
    except User.DoesNotExist:
        # For security, return success even if user doesn't exist
        # This prevents email enumeration attacks
        return Response({'message': 'Password reset email sent successfully'})
    except Exception as e:
        logger.error(f"Password reset email error: {str(e)}")
        return Response(
            {'error': 'Failed to send password reset email. Please try again.'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def confirm_password_reset(request):
    """Confirm password reset with token"""
    token = request.data.get('token')
    uid = request.data.get('uid')
    new_password = request.data.get('new_password')
    
    if not all([token, uid, new_password]):
        return Response(
            {'error': 'Token, UID, and new password are required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Decode user ID
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
        
        # Check if token is valid
        if not default_token_generator.check_token(user, token):
            return Response(
                {'error': 'Invalid or expired password reset link'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate password
        if len(new_password) < 8:
            return Response(
                {'password': ['Password must be at least 8 characters long']}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        logger.info(f"Password reset successful for {user.email}")
        
        return Response({'message': 'Password reset successful'})
        
    except (User.DoesNotExist, ValueError):
        return Response(
            {'error': 'Invalid password reset link'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        logger.error(f"Password reset confirmation error: {str(e)}")
        return Response(
            {'error': 'Failed to reset password. Please try again.'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_connected_accounts(request):
    """Return connected social accounts for the logged-in user"""
    user = request.user
    providers = ['google-oauth2', 'github', 'microsoft']

    connected = {provider.split('-')[0]: False for provider in providers}

    for profile in user.social_profiles.all():
        short_name = profile.provider.split('-')[0]  # e.g., "google" from "google-oauth2"
        if short_name in connected:
            connected[short_name] = True

    return Response(connected)
