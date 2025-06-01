# compliance/services/compliance_service.py - Complete compliance service

from django.utils import timezone
from django.contrib.auth import get_user_model
from django.conf import settings
from urllib.parse import urlparse
import logging

from ..models import (
    DomainAuthorization, 
    UserComplianceStatus, 
    PreauthorizedDomain,
    ComplianceAgreement
)

logger = logging.getLogger(__name__)

User = get_user_model()

class ComplianceService:
    """Complete compliance service for domain authorization and legal compliance"""
    
    def __init__(self, user):
        self.user = user
    
    def has_accepted_required_agreements(self):
        """Check if user has accepted minimum required agreements for passive scanning"""
        compliance_status, created = UserComplianceStatus.objects.get_or_create(
            user=self.user,
            defaults={
                'terms_accepted': False,
                'privacy_accepted': False,
                'responsible_disclosure_accepted': False,
                'active_scanning_accepted': False,
            }
        )
        
        return (
            compliance_status.terms_accepted and
            compliance_status.privacy_accepted and
            compliance_status.responsible_disclosure_accepted
        )
    
    def has_accepted_active_scanning_agreement(self):
        """Check if user has accepted active scanning legal agreement"""
        if not self.has_accepted_required_agreements():
            return False
        
        compliance_status, created = UserComplianceStatus.objects.get_or_create(user=self.user)
        return compliance_status.active_scanning_accepted
    
    def get_missing_agreements(self):
        """Get list of missing agreements"""
        compliance_status, created = UserComplianceStatus.objects.get_or_create(user=self.user)
        
        missing = []
        if not compliance_status.terms_accepted:
            missing.append('terms_of_service')
        if not compliance_status.privacy_accepted:
            missing.append('privacy_policy')
        if not compliance_status.responsible_disclosure_accepted:
            missing.append('responsible_disclosure')
        
        return missing
    
    def is_preauthorized_domain(self, url_or_domain):
        """Check if domain is pre-authorized for testing"""
        if url_or_domain.startswith(('http://', 'https://')):
            return PreauthorizedDomain.is_preauthorized(url_or_domain)
        else:
            # If it's just a domain, construct a URL
            return PreauthorizedDomain.is_preauthorized(f"https://{url_or_domain}")
    
    def can_scan_domain(self, url_or_domain, scan_mode='passive'):
        """Check if user can scan a domain with specified mode"""
        # Extract domain from URL if needed
        if url_or_domain.startswith(('http://', 'https://')):
            domain = urlparse(url_or_domain).netloc
            full_url = url_or_domain
        else:
            domain = url_or_domain
            full_url = f"https://{domain}"
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        if scan_mode == 'passive':
            # Passive scans only require basic agreements
            if not self.has_accepted_required_agreements():
                return False, "Must accept required legal agreements for passive scanning"
            return True, "Passive scanning authorized"
        
        elif scan_mode in ['active', 'mixed']:
            # Active scans require additional checks
            if not self.has_accepted_active_scanning_agreement():
                return False, "Must accept Active Scanning Legal Agreement"
            
            # Pre-authorized domains don't need additional verification
            if self.is_preauthorized_domain(full_url):
                return True, "Active scanning authorized for pre-authorized test domain"
            
            # Production domains need domain authorization
            domain_auth = self.get_domain_authorization(domain)
            if not domain_auth:
                return False, f"No domain authorization found for {domain}. Please verify domain ownership."
            
            if domain_auth.status != 'verified':
                return False, f"Domain authorization for {domain} is not verified (status: {domain_auth.status})"
            
            # Check if active (not expired)
            if not domain_auth.is_active:
                return False, f"Domain authorization for {domain} is not active"
            
            return True, f"Active scanning authorized via {getattr(domain_auth, 'verification_method', 'domain verification')}"
        
        return False, f"Unknown scan mode: {scan_mode}"
    
    def get_domain_authorization(self, domain):
        """Get valid authorization for a domain"""
        try:
            auth = DomainAuthorization.objects.filter(
                user=self.user,
                domain=domain,
                status='verified'
            ).order_by('-verified_at').first()
            
            return auth
            
        except Exception as e:
            logger.warning(f"Error accessing DomainAuthorization for domain {domain}: {e}")
            return None
    
    def request_domain_authorization(self, domain, verification_method='dns_txt'):
        """Request domain authorization"""
        # Check if already exists
        existing = DomainAuthorization.objects.filter(
            user=self.user, 
            domain=domain
        ).first()
        
        if existing and existing.status in ['verified', 'pending']:
            return existing, f'Domain {domain} already has authorization status: {existing.status}'
        
        # Generate verification token
        import secrets
        import string
        verification_token = ''.join(
            secrets.choice(string.ascii_letters + string.digits) 
            for _ in range(32)
        )
        
        # Create authorization request
        auth = DomainAuthorization.objects.create(
            user=self.user,
            domain=domain,
            verification_method=verification_method,
            verification_token=verification_token,
            status='pending'
        )
        
        # Set verification data based on method
        if verification_method == 'dns_txt':
            auth.verification_data = {
                'txt_record': f'site-analyser-verify={verification_token}',
                'instructions': f'Add this TXT record to your DNS: site-analyser-verify={verification_token}'
            }
        elif verification_method == 'file_upload':
            auth.verification_data = {
                'file_name': f'site-analyser-{verification_token}.txt',
                'file_content': verification_token,
                'instructions': f'Upload a file named "site-analyser-{verification_token}.txt" containing "{verification_token}" to your website root'
            }
        
        auth.save()
        
        return auth, f'Domain authorization requested for {domain}'
    
    def verify_domain_authorization(self, domain_id):
        """Verify a domain authorization"""
        try:
            auth = DomainAuthorization.objects.get(
                id=domain_id,
                user=self.user,
                status='pending'
            )
        except DomainAuthorization.DoesNotExist:
            return False, 'Domain authorization not found or already processed'
        
        # Here you would implement actual verification logic
        # For now, we'll simulate verification
        verification_success = True  # Placeholder
        
        if verification_success:
            auth.status = 'verified'
            auth.verified_at = timezone.now()
            # Set expiration to 1 year from now
            auth.expires_at = timezone.now() + timezone.timedelta(days=365)
            auth.save()
            
            return True, f'Domain {auth.domain} successfully verified!'
        else:
            return False, 'Domain verification failed'
    
    def get_compliance_status(self):
        """Get comprehensive compliance status for user"""
        compliance_status, created = UserComplianceStatus.objects.get_or_create(
            user=self.user,
            defaults={
                'terms_accepted': False,
                'privacy_accepted': False,
                'responsible_disclosure_accepted': False,
                'active_scanning_accepted': False,
            }
        )
        
        # Get domain authorizations
        domain_auths = DomainAuthorization.objects.filter(
            user=self.user,
            status='verified'
        )
        
        authorized_domains = []
        for auth in domain_auths:
            if auth.is_active:
                authorized_domains.append({
                    'domain': auth.domain,
                    'verification_method': auth.verification_method,
                    'verified_at': auth.verified_at.isoformat() if auth.verified_at else None,
                    'expires_at': auth.expires_at.isoformat() if auth.expires_at else None,
                    'is_expired': not auth.is_active
                })
        
        # Calculate compliance score
        compliance_score = self._calculate_compliance_score()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Get agreement status
        missing_agreements = self.get_missing_agreements()
        has_active_agreement = compliance_status.active_scanning_accepted
        has_basic_agreements = len(missing_agreements) == 0
        
        can_active_scan = (
            has_basic_agreements and 
            has_active_agreement and 
            len(authorized_domains) > 0
        )
        
        return {
            'user_id': self.user.id,
            'username': self.user.username,
            'compliance_score': compliance_score,
            
            # Agreement status
            'all_agreements_accepted': has_basic_agreements and has_active_agreement,
            'missing_agreements': missing_agreements,
            'agreements': {
                'terms_of_service': compliance_status.terms_accepted,
                'privacy_policy': compliance_status.privacy_accepted,
                'responsible_disclosure': compliance_status.responsible_disclosure_accepted,
                'active_scanning': has_active_agreement,
            },
            
            # Scanning capabilities
            'can_passive_scan': has_basic_agreements,
            'can_active_scan': can_active_scan,
            'authorized_domains': authorized_domains,
            
            'scan_capabilities': {
                'passive_enabled': has_basic_agreements,
                'active_enabled': can_active_scan,
                'mixed_enabled': can_active_scan,
                'note': 'Active/Mixed scanning requires domain authorization' if not can_active_scan else None
            },
            
            'recommendations': recommendations,
        }
    
    def check_url_authorization(self, url):
        """Check what scan modes are available for a specific URL"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check if it's a pre-authorized domain
            is_preauth = self.is_preauthorized_domain(url)
            
            # Check user's compliance status
            has_basic_agreements = self.has_accepted_required_agreements()
            has_active_agreement = self.has_accepted_active_scanning_agreement()
            
            # Check domain authorization
            domain_auth = self.get_domain_authorization(domain)
            has_domain_auth = bool(domain_auth)
            
            # For pre-authorized domains, we don't need domain auth
            active_enabled = has_active_agreement and (is_preauth or has_domain_auth)
            
            # Determine capabilities
            passive_enabled = has_basic_agreements
            
            # Generate reason text
            if not has_basic_agreements:
                reason = "Must accept basic legal agreements"
            elif not has_active_agreement:
                reason = "Must accept Active Scanning Agreement for active/mixed scans"
            elif not is_preauth and not has_domain_auth:
                reason = f"Must verify ownership of {domain} for active scanning"
            else:
                reason = "All scan modes available"
            
            return {
                'url': url,
                'domain': domain,
                'is_preauthorized': is_preauth,
                'scan_capabilities': {
                    'passive_enabled': passive_enabled,
                    'active_enabled': active_enabled,
                    'mixed_enabled': active_enabled,
                    'reason': reason
                },
                'domain_authorization': {
                    'required': not is_preauth,
                    'verified': has_domain_auth,
                    'method': getattr(domain_auth, 'verification_method', None) if domain_auth else None
                } if not is_preauth else None
            }
            
        except Exception as e:
            logger.error(f"Error checking URL authorization for {url}: {e}")
            return {
                'url': url,
                'domain': 'unknown',
                'scan_capabilities': {
                    'passive_enabled': False,
                    'active_enabled': False,
                    'mixed_enabled': False,
                    'reason': 'Error checking authorization'
                }
            }
    
    def generate_scan_compliance_report(self, scan, results):
        """Generate compliance report for a scan"""
        from urllib.parse import urlparse
        
        domain = urlparse(scan.target_url).netloc
        
        # Get scan statistics
        result_stats = {}
        if results:
            from django.db.models import Count
            result_stats = dict(
                results.values('severity')
                .annotate(count=Count('severity'))
                .values_list('severity', 'count')
            )
        
        # Check authorization status
        auth_status = {
            'required': scan.requires_authorization() if hasattr(scan, 'requires_authorization') else False,
            'authorized': scan.is_authorized() if hasattr(scan, 'is_authorized') else True,
        }
        
        if scan.authorization:
            auth_status.update({
                'method': getattr(scan.authorization, 'verification_method', 'unknown'),
                'verified_at': getattr(scan.authorization, 'verified_at', None),
                'expires_at': getattr(scan.authorization, 'expires_at', None)
            })
        
        return {
            'scan_id': str(scan.id),
            'target_url': scan.target_url,
            'domain': domain,
            'scan_mode': getattr(scan, 'scan_mode', 'passive'),
            'compliance_mode': getattr(scan, 'compliance_mode', 'strict'),
            'status': scan.status,
            'created_at': scan.created_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            
            'authorization_status': auth_status,
            'is_preauthorized': self.is_preauthorized_domain(scan.target_url),
            
            'compliance_summary': {
                'terms_accepted': getattr(scan, 'terms_accepted', True),
                'authorization_valid': auth_status['authorized'],
                'compliance_violations': getattr(scan, 'compliance_violations', []),
                'requests_made': getattr(scan, 'requests_made', 0),
                'pages_scanned': getattr(scan, 'pages_scanned', 0)
            },
            
            'results_summary': {
                'total_findings': len(results) if results else 0,
                'by_severity': result_stats
            }
        }
    
    def _calculate_compliance_score(self):
        """Calculate compliance score (0-100)"""
        score = 0
        
        # Basic agreements (40 points)
        if self.has_accepted_required_agreements():
            score += 40
        
        # Active scanning agreement (20 points)
        if self.has_accepted_active_scanning_agreement():
            score += 20
        
        # Valid domain authorizations (20 points)
        try:
            valid_auths = DomainAuthorization.objects.filter(
                user=self.user,
                status='verified'
            )
            valid_auth_count = sum(1 for auth in valid_auths if auth.is_active)
        except:
            valid_auth_count = 0
        
        if valid_auth_count > 0:
            score += min(20, valid_auth_count * 5)
        
        # No recent violations (20 points)
        try:
            # Import here to avoid circular imports
            from scanner.models import SecurityAuditLog
            recent_violations = SecurityAuditLog.objects.filter(
                user=self.user,
                event_type='compliance_violation',
                timestamp__gte=timezone.now() - timezone.timedelta(days=30)
            ).count()
            
            if recent_violations == 0:
                score += 20
            else:
                score += max(0, 20 - (recent_violations * 5))
        except:
            score += 20  # If no audit log, assume no violations
        
        return min(100, score)
    
    def _generate_recommendations(self):
        """Generate compliance recommendations for user"""
        recommendations = []
        
        compliance_status, created = UserComplianceStatus.objects.get_or_create(user=self.user)
        
        # Basic agreement recommendations
        if not self.has_accepted_required_agreements():
            missing = []
            if not compliance_status.terms_accepted:
                missing.append('Terms of Service')
            if not compliance_status.privacy_accepted:
                missing.append('Privacy Policy')
            if not compliance_status.responsible_disclosure_accepted:
                missing.append('Responsible Disclosure')
            
            recommendations.append({
                'type': 'required',
                'priority': 'high',
                'title': 'Accept Required Legal Agreements',
                'description': f'You must accept the following agreements to use scanning features: {", ".join(missing)}',
                'action': 'Go to Compliance page and accept required agreements'
            })
        
        # Active scanning recommendations
        if self.has_accepted_required_agreements() and not self.has_accepted_active_scanning_agreement():
            recommendations.append({
                'type': 'enhancement',
                'priority': 'medium',
                'title': 'Enable Active Scanning',
                'description': 'Accept the Active Scanning Legal Agreement to unlock advanced vulnerability testing',
                'action': 'Review and accept the Active Scanning Agreement'
            })
        
        # Domain authorization recommendations
        if self.has_accepted_active_scanning_agreement():
            try:
                valid_auths = DomainAuthorization.objects.filter(
                    user=self.user,
                    status='verified'
                )
                valid_auth_count = sum(1 for auth in valid_auths if auth.is_active)
            except:
                valid_auth_count = 0
            
            if valid_auth_count == 0:
                recommendations.append({
                    'type': 'enhancement',
                    'priority': 'medium',
                    'title': 'Set Up Domain Authorization',
                    'description': 'Verify ownership of your domains to enable active scanning on your websites',
                    'action': 'Go to Domain Authorization page and verify your domains'
                })
        
        return recommendations