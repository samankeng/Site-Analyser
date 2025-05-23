# server/accounts/pipeline.py

from django.contrib.auth import get_user_model
from .models import SocialAuthProfile

User = get_user_model()

def create_social_profile(strategy, details, response, user=None, *args, **kwargs):
    """
    Create or update social auth profile for the user
    """
    if user:
        backend_name = kwargs['backend'].name
        
        # Extract social data based on provider
        social_data = {}
        
        if backend_name == 'google-oauth2':
            social_data = {
                'first_name': details.get('first_name', ''),
                'last_name': details.get('last_name', ''),
                'avatar_url': response.get('picture', ''),
                'social_id': response.get('sub', ''),
            }
        elif backend_name == 'github':
            social_data = {
                'first_name': details.get('first_name', ''),
                'last_name': details.get('last_name', ''),
                'avatar_url': response.get('avatar_url', ''),
                'social_id': str(response.get('id', '')),
            }
        
        # Update user fields
        user.is_social_account = True
        user.social_provider = backend_name
        
        # Use the merge_social_data method if it exists
        if hasattr(user, 'merge_social_data'):
            user.merge_social_data(social_data)
        else:
            # Fallback manual merge
            if not user.first_name and social_data.get('first_name'):
                user.first_name = social_data['first_name']
            
            if not user.last_name and social_data.get('last_name'):
                user.last_name = social_data['last_name']
            
            if social_data.get('avatar_url'):
                user.avatar_url = social_data['avatar_url']
            
            user.save()
        
        # Create or update social auth profile
        social_profile, created = SocialAuthProfile.objects.get_or_create(
            user=user,
            provider=backend_name,
            defaults={
                'social_id': social_data.get('social_id', ''),
                'extra_data': response
            }
        )
        
        if not created:
            social_profile.extra_data = response
            social_profile.save()
        
        # Generate API key if not exists and method is available
        if not user.api_key and hasattr(user, 'generate_api_key'):
            user.generate_api_key()
    
    return kwargs

def require_email(strategy, details, user=None, *args, **kwargs):
    """
    Require email from social providers
    """
    if not details.get('email'):
        return strategy.redirect('/auth/error/?error=no_email')
    return kwargs

def check_existing_email(strategy, details, user=None, *args, **kwargs):
    """
    Check if email already exists and merge accounts if needed
    """
    email = details.get('email')
    if email:
        try:
            existing_user = User.objects.get(email=email)
            if existing_user and not user:
                # Email exists, associate this social account with existing user
                return {'user': existing_user}
        except User.DoesNotExist:
            pass
    return kwargs