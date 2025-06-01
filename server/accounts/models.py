# server/accounts/models.py - Updated with email verification

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta
import uuid
import secrets
import string

class User(AbstractUser):
    """Custom user model for Site Analyser with social auth and email verification support"""
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
    
    # Email verification fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=64, blank=True)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)
    
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
    
    def generate_email_verification_token(self):
        """Generate a new email verification token"""
        alphabet = string.ascii_letters + string.digits
        self.email_verification_token = ''.join(secrets.choice(alphabet) for _ in range(64))
        self.email_verification_sent_at = timezone.now()
        self.save()
        return self.email_verification_token
    
    def is_email_verification_expired(self):
        """Check if email verification token has expired (24 hours)"""
        if not self.email_verification_sent_at:
            return True
        expiry_time = self.email_verification_sent_at + timedelta(hours=24)
        return timezone.now() > expiry_time
    
    def verify_email(self):
        """Mark email as verified and clear verification token"""
        self.is_email_verified = True
        self.email_verification_token = ''
        self.email_verification_sent_at = None
        self.save()
    
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
        
        # Social accounts are considered email verified
        if not self.is_email_verified:
            self.is_email_verified = True
        
        self.save()

    def save(self, *args, **kwargs):
        # Social accounts are automatically email verified
        if self.is_social_account and not self.is_email_verified:
            self.is_email_verified = True
        
        super().save(*args, **kwargs)

class SocialAuthProfile(models.Model):
    """Extended profile for social authentication"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_profiles')
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

class EmailVerificationAttempt(models.Model):
    """Track email verification attempts to prevent abuse"""
    email = models.EmailField()
    attempts_count = models.IntegerField(default=1)
    last_attempt = models.DateTimeField(auto_now=True)
    blocked_until = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ('email',)
    
    def is_blocked(self):
        """Check if email is currently blocked from verification attempts"""
        if self.blocked_until and timezone.now() < self.blocked_until:
            return True
        return False
    
    def can_send_verification(self):
        """Check if verification email can be sent"""
        if self.is_blocked():
            return False
        
        # Allow 3 attempts per hour
        one_hour_ago = timezone.now() - timedelta(hours=1)
        if self.last_attempt > one_hour_ago and self.attempts_count >= 3:
            # Block for 1 hour
            self.blocked_until = timezone.now() + timedelta(hours=1)
            self.save()
            return False
        
        # Reset counter if more than an hour has passed
        if self.last_attempt <= one_hour_ago:
            self.attempts_count = 0
        
        return True
    
    def record_attempt(self):
        """Record a verification attempt"""
        if self.last_attempt <= timezone.now() - timedelta(hours=1):
            self.attempts_count = 1
        else:
            self.attempts_count += 1
        self.last_attempt = timezone.now()
        self.save()