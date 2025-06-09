# server/accounts/serializers.py - Complete version with all serializers

from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import SocialAuthProfile

User = get_user_model()

class SocialAuthProfileSerializer(serializers.ModelSerializer):
    """Serializer for social auth profile"""
    
    class Meta:
        model = SocialAuthProfile
        fields = ('provider', 'social_id', 'created_at')
        read_only_fields = ('provider', 'social_id', 'created_at')

class UserSerializer(serializers.ModelSerializer):
    """Serializer for user objects with social auth support"""
    social_profiles = serializers.SerializerMethodField()
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = (
            'id', 'email', 'username', 'first_name', 'last_name', 
            'company', 'job_title', 'date_joined', 'avatar_url',
            'is_social_account', 'social_provider', 'profile_completed',
            'full_name', 'social_profiles', 'api_key', 'is_email_verified',
            'is_staff', 'is_superuser', 'is_active'  # ← ADD THESE CRITICAL FIELDS
        )
        read_only_fields = (
            'id', 'date_joined', 'is_social_account', 'social_provider', 
            'api_key', 'username', 'is_staff', 'is_superuser', 'is_active'  # ← MAKE ADMIN FIELDS READ-ONLY
        )
    
    def get_social_profiles(self, obj):
        """Get user's social auth profiles"""
        try:
            profiles = SocialAuthProfile.objects.filter(user=obj)
            return SocialAuthProfileSerializer(profiles, many=True).data
        except:
            return []

class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm', 
                  'first_name', 'last_name', 'company', 'job_title')
        # Removed username from fields since we'll set it automatically
    
    def validate_email(self, value):
        """Validate email is unique"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value
    
    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        """Create user with email as username"""
        validated_data.pop('password_confirm')
        
        # Set username to email to satisfy Django's requirements
        validated_data['username'] = validated_data['email']
        
        user = User.objects.create_user(**validated_data)
        
        # Generate API key for new users
        if hasattr(user, 'generate_api_key'):
            user.generate_api_key()
        
        return user

class SocialAuthTokenSerializer(serializers.Serializer):
    """Serializer for social auth token exchange"""
    provider = serializers.CharField(max_length=50)
    access_token = serializers.CharField()
    
    def validate_provider(self, value):
        allowed_providers = ['google-oauth2', 'github', 'microsoft']
        if value not in allowed_providers:
            raise serializers.ValidationError(f"Provider must be one of: {', '.join(allowed_providers)}")
        return value

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom token serializer that includes user data"""
    username_field = 'email'  # Tell Django to use email as username field
    
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        serializer = UserSerializer(user)
        data.update({'user': serializer.data})
        return data

class ProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'company', 'job_title')
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        # Mark profile as completed if all required fields are filled
        if (instance.first_name and instance.last_name and 
            instance.company and instance.job_title):
            instance.profile_completed = True
        
        instance.save()
        return instance