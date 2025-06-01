# ============================================
# compliance/models.py - FIXED VERSION
# ============================================

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from urllib.parse import urlparse
import re

User = get_user_model()

class ComplianceAgreement(models.Model):
    """Legal agreements that users must accept"""
    AGREEMENT_TYPES = [
        ('terms_of_service', 'Terms of Service'),
        ('privacy_policy', 'Privacy Policy'), 
        ('responsible_disclosure', 'Responsible Disclosure Agreement'),
        ('active_scanning', 'Active Scanning Agreement'),
    ]
    
    agreement_type = models.CharField(max_length=50, choices=AGREEMENT_TYPES, unique=True)
    title = models.CharField(max_length=200)
    content = models.TextField()
    version = models.CharField(max_length=20, default='1.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_required = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.title} v{self.version}"

class DomainAuthorization(models.Model):
    """Domain ownership/authorization for active scanning"""
    VERIFICATION_METHODS = [
        ('dns_txt', 'DNS TXT Record'),
        ('file_upload', 'File Upload Verification'),
        ('email_verification', 'Email Verification'),
        ('manual_approval', 'Manual Admin Approval'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending Verification'),
        ('verified', 'Verified'),
        ('expired', 'Expired'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='domain_authorizations')
    domain = models.CharField(max_length=255)  # e.g., "example.com"
    subdomain_pattern = models.CharField(max_length=255, blank=True)  # e.g., "*.example.com" 
    
    # Verification details
    verification_method = models.CharField(max_length=50, choices=VERIFICATION_METHODS)
    verification_token = models.CharField(max_length=128, blank=True)
    verification_data = models.JSONField(default=dict)  # Store verification-specific data
    
    # Status and timing
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    # Admin fields
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='approved_domains'
    )
    notes = models.TextField(blank=True)
    
    class Meta:
        unique_together = ('user', 'domain')
    
    def __str__(self):
        return f"{self.domain} - {self.user.email} - {self.status}"
    
    def is_valid(self):
        """Check if authorization is currently valid - ADDED METHOD TO FIX ERROR"""
        if self.status != 'verified':
            return False
        
        if self.expires_at and timezone.now() > self.expires_at:
            # Auto-expire if past expiration date
            self.status = 'expired'
            self.save()
            return False
        
        return True
    
    @property
    def is_active(self):
        """Check if authorization is currently active"""
        return self.is_valid()  # Use is_valid() method for consistency
    
    # Add setter for is_active to fix the "can't set attribute" error
    @is_active.setter
    def is_active(self, value):
        """Allow setting is_active property"""
        if value:
            if self.status != 'verified':
                self.status = 'verified'
            if self.verified_at is None:
                self.verified_at = timezone.now()
        else:
            self.status = 'rejected'
    
    # Add is_verified property for backward compatibility
    @property
    def is_verified(self):
        """Check if domain is verified (alias for status == 'verified')"""
        return self.status == 'verified'
    
    # Add is_approved property for compatibility with ScanAuthorization interface
    @property
    def is_approved(self):
        """Check if domain is approved (alias for status == 'verified')"""
        return self.status == 'verified'
    
    def matches_url(self, url):
        """Check if this authorization covers the given URL"""
        if not self.is_valid():
            return False
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower()
            
            # Exact domain match
            if hostname == self.domain.lower():
                return True
            
            # Subdomain pattern match
            if self.subdomain_pattern:
                pattern = self.subdomain_pattern.replace('*', '.*')
                if re.match(pattern, hostname):
                    return True
            
            # Check if it's a subdomain of authorized domain
            if hostname.endswith('.' + self.domain.lower()):
                return True
                
        except Exception:
            return False
        
        return False

class PreauthorizedDomain(models.Model):
    """Domains that are pre-authorized for testing (like test sites)"""
    domain = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=500)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.domain} (Pre-authorized)"
    
    @classmethod
    def is_preauthorized(cls, url):
        """Check if URL is in pre-authorized domains"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower()
            
            # Check exact matches and parent domains
            for domain in cls.objects.filter(is_active=True):
                if (hostname == domain.domain.lower() or 
                    hostname.endswith('.' + domain.domain.lower())):
                    return True
        except Exception:
            pass
        
        return False

class UserComplianceStatus(models.Model):
    """Track user's compliance with various agreements"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='compliance_status')
    
    # Agreement acceptances
    terms_accepted = models.BooleanField(default=False)
    terms_accepted_at = models.DateTimeField(null=True, blank=True)
    
    privacy_accepted = models.BooleanField(default=False) 
    privacy_accepted_at = models.DateTimeField(null=True, blank=True)
    
    responsible_disclosure_accepted = models.BooleanField(default=False)
    responsible_disclosure_accepted_at = models.DateTimeField(null=True, blank=True)
    
    active_scanning_accepted = models.BooleanField(default=False)
    active_scanning_accepted_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Compliance for {self.user.email}"
    
    @property
    def all_agreements_accepted(self):
        """Check if all required agreements are accepted"""
        return (
            self.terms_accepted and
            self.privacy_accepted and 
            self.responsible_disclosure_accepted
        )
    
    @property
    def can_active_scan(self):
        """Check if user can perform active scanning (has agreements)"""
        return (
            self.all_agreements_accepted and 
            self.active_scanning_accepted
        )
    
    @property
    def missing_agreements(self):
        """Get list of missing agreements"""
        missing = []
        if not self.terms_accepted:
            missing.append('terms_of_service')
        if not self.privacy_accepted:
            missing.append('privacy_policy')
        if not self.responsible_disclosure_accepted:
            missing.append('responsible_disclosure')
        return missing
    
    def get_scan_capabilities_for_url(self, url):
        """Get scan capabilities for a specific URL"""
        # Basic passive scanning
        capabilities = {
            'passive_enabled': self.all_agreements_accepted,
            'active_enabled': False,
            'mixed_enabled': False,
            'reason': None
        }
        
        if not self.can_active_scan:
            capabilities['reason'] = 'Active Scanning Agreement required'
            return capabilities
        
        # Check if URL is pre-authorized (test domains)
        if PreauthorizedDomain.is_preauthorized(url):
            capabilities.update({
                'active_enabled': True,
                'mixed_enabled': True,
                'reason': 'Pre-authorized test domain'
            })
            return capabilities
        
        # Check user's domain authorizations - FIXED: Use correct status
        user_domains = DomainAuthorization.objects.filter(
            user=self.user,
            status='verified'  # ✅ This is correct - 'verified' is the approved status
        )
        
        for domain_auth in user_domains:
            if domain_auth.matches_url(url):
                capabilities.update({
                    'active_enabled': True,
                    'mixed_enabled': True,
                    'reason': f'Authorized domain: {domain_auth.domain}'
                })
                return capabilities
        
        capabilities['reason'] = 'Domain authorization required for active scanning'
        return capabilities