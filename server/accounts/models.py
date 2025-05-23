# server/accounts/models.py - Updated

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
import uuid
import secrets
import string

class User(AbstractUser):
    """Custom user model for Site Analyser with social auth support"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    
    # Additional fields
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    api_key = models.CharField(max_length=64, blank=True)
    
    # Social auth fields
    avatar_url = models.URLField(blank=True, null=True)
    is_social_account = models.BooleanField(default=False)
    social_provider = models.CharField(max_length=50, blank=True)
    
    # Profile completion
    profile_completed = models.BooleanField(default=False)
    
    # Set email as the main identifier for authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']

    def __str__(self):
        return self.email
    
    def generate_api_key(self):
        """Generate a new API key for the user"""
        alphabet = string.ascii_letters + string.digits
        self.api_key = ''.join(secrets.choice(alphabet) for _ in range(64))
        self.save()
        return self.api_key
    
    def get_full_name(self):
        """Return the user's full name or email if names are not available"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        return self.email
    
    def merge_social_data(self, social_data):
        """Merge social authentication data with existing profile"""
        if not self.first_name and social_data.get('first_name'):
            self.first_name = social_data['first_name']
        
        if not self.last_name and social_data.get('last_name'):
            self.last_name = social_data['last_name']
        
        if social_data.get('avatar_url'):
            self.avatar_url = social_data['avatar_url']
        
        self.save()

class SocialAuthProfile(models.Model):
    """Extended profile for social authentication"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='social_profile')
    provider = models.CharField(max_length=50)
    social_id = models.CharField(max_length=100)
    access_token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    extra_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('user', 'provider')
    
    def __str__(self):
        return f"{self.user.email} - {self.provider}"