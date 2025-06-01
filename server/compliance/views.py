# compliance/views.py - COMPLETE VERSION with all functionality

from rest_framework import status, viewsets, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.utils import timezone
from django.conf import settings
from urllib.parse import urlparse
from .models import (
    ComplianceAgreement, 
    UserComplianceStatus, 
    DomainAuthorization,
    PreauthorizedDomain
)
from .services.compliance_service import ComplianceService
import secrets
import string
import logging

logger = logging.getLogger(__name__)

# ========== COMPLIANCE STATUS AND AGREEMENTS ==========

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def compliance_status(request):
    """Get user's current compliance status"""
    try:
        service = ComplianceService(request.user)
        status_data = service.get_compliance_status()
        return Response(status_data)
    except Exception as e:
        logger.error(f"Error getting compliance status for user {request.user.username}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated]) 
def check_url_authorization(request):
    """Check what scan modes are available for a specific URL"""
    url = request.data.get('url')
    
    if not url:
        return Response(
            {'error': 'URL is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Add protocol if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return Response(
                {'error': 'Invalid URL format'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception:
        return Response(
            {'error': 'Invalid URL format'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        service = ComplianceService(request.user)
        authorization_data = service.check_url_authorization(url)
        return Response(authorization_data)
    except Exception as e:
        logger.error(f"Error checking URL authorization: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_modes(request):
    """Get available scan modes with descriptions"""
    return Response({
        'passive': {
            'name': 'Passive Scan',
            'description': 'Safe, non-intrusive scanning that can be performed on any website',
            'legal_risk': 'Very Low',
            'authorization_required': False,
            'requirements': [
                'Accept Terms of Service',
                'Accept Privacy Policy', 
                'Accept Responsible Disclosure Agreement'
            ]
        },
        'active': {
            'name': 'Active Scan',
            'description': 'Intrusive testing that may trigger security alerts - requires domain authorization',
            'legal_risk': 'High',
            'authorization_required': True,
            'requirements': [
                'Accept all legal agreements',
                'Accept Active Scanning Agreement',
                'Verify domain ownership OR target pre-authorized test domains'
            ]
        },
        'mixed': {
            'name': 'Mixed Scan',
            'description': 'Combines passive and active testing with intelligent authorization checks',
            'legal_risk': 'Medium',
            'authorization_required': True,
            'requirements': [
                'Accept all legal agreements',
                'Accept Active Scanning Agreement',
                'Verify domain ownership OR target pre-authorized test domains'
            ]
        }
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def accept_agreement(request):
    """Accept a specific legal agreement"""
    agreement_type = request.data.get('agreement_type')
    
    if not agreement_type:
        return Response(
            {'error': 'agreement_type is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = request.user
    compliance, created = UserComplianceStatus.objects.get_or_create(user=user)
    
    now = timezone.now()
    
    # Update the specific agreement
    if agreement_type == 'terms_of_service':
        compliance.terms_accepted = True
        compliance.terms_accepted_at = now
    elif agreement_type == 'privacy_policy':
        compliance.privacy_accepted = True
        compliance.privacy_accepted_at = now
    elif agreement_type == 'responsible_disclosure':
        compliance.responsible_disclosure_accepted = True
        compliance.responsible_disclosure_accepted_at = now
    elif agreement_type == 'active_scanning':
        compliance.active_scanning_accepted = True
        compliance.active_scanning_accepted_at = now
    else:
        return Response(
            {'error': 'Invalid agreement_type'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    compliance.save()
    
    # Log agreement acceptance
    try:
        from scanner.models import SecurityAuditLog
        SecurityAuditLog.objects.create(
            event_type='admin_action',
            severity='low',
            user=request.user,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            message=f'User accepted {agreement_type} agreement',
            event_data={'agreement_type': agreement_type}
        )
    except ImportError:
        pass  # SecurityAuditLog not available
    
    return Response({
        'message': f'{agreement_type} agreement accepted successfully',
        'can_active_scan': compliance.can_active_scan
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legal_notices(request):
    """Get all legal notices and agreements"""
    notices = getattr(settings, 'SCANNER_LEGAL_NOTICES', {})
    return Response(notices)

# ========== DOMAIN AUTHORIZATION ==========

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_domain_authorization(request):
    """Request authorization for a domain"""
    domain = request.data.get('domain')
    verification_method = request.data.get('verification_method', 'dns_txt')
    
    if not domain:
        return Response(
            {'error': 'Domain is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Clean domain name
    domain = domain.lower().strip()
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urlparse(domain)
        domain = parsed.hostname
    
    try:
        service = ComplianceService(request.user)
        auth, message = service.request_domain_authorization(domain, verification_method)
        
        return Response({
            'message': message,
            'verification_method': verification_method,
            'verification_data': auth.verification_data,
            'domain_id': auth.id
        })
    except Exception as e:
        logger.error(f"Error requesting domain authorization: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_domain_authorization(request):
    """Verify a domain authorization"""
    domain_id = request.data.get('domain_id')
    
    if not domain_id:
        return Response(
            {'error': 'domain_id is required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        service = ComplianceService(request.user)
        success, message = service.verify_domain_authorization(domain_id)
        
        if success:
            return Response({'message': message})
        else:
            return Response({'error': message}, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        logger.error(f"Error verifying domain authorization: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_domain_authorizations(request):
    """List user's domain authorizations"""
    try:
        authorizations = DomainAuthorization.objects.filter(user=request.user).order_by('-requested_at')
        
        results = []
        for auth in authorizations:
            auth_data = {
                'id': str(auth.id),
                'domain': auth.domain,
                'verification_method': auth.verification_method,
                'status': auth.status,
                'is_verified': auth.status == 'verified',
                'is_approved': auth.status == 'verified',
                'is_active': auth.is_active,
                'created_at': auth.requested_at.isoformat(),
                'requested_at': auth.requested_at.isoformat(),
                'verification_token': auth.verification_token,
                'verification_data': auth.verification_data,
                'notes': auth.notes,
            }
            
            if auth.expires_at:
                auth_data['expires_at'] = auth.expires_at.isoformat()
                auth_data['valid_until'] = auth.expires_at.isoformat()
            
            if auth.verified_at:
                auth_data['verified_at'] = auth.verified_at.isoformat()
            
            if auth.approved_by:
                auth_data['approved_by_username'] = auth.approved_by.username
                auth_data['approved_at'] = auth.verified_at.isoformat() if auth.verified_at else None
            
            results.append(auth_data)
        
        return Response({
            'count': len(results),
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error listing domain authorizations for user {request.user.username}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
def domain_authorization_detail(request, auth_id):
    """Get, update, or delete a specific domain authorization"""
    try:
        if request.user.is_staff or request.user.is_superuser:
            auth = DomainAuthorization.objects.get(id=auth_id)
        else:
            auth = DomainAuthorization.objects.get(id=auth_id, user=request.user)
        
        if request.method == 'GET':
            auth_data = {
                'id': str(auth.id),
                'domain': auth.domain,
                'verification_method': auth.verification_method,
                'status': auth.status,
                'is_verified': auth.status == 'verified',
                'is_active': auth.is_active,
                'created_at': auth.requested_at.isoformat(),
                'requested_at': auth.requested_at.isoformat(),
                'verification_token': auth.verification_token,
                'verification_data': auth.verification_data,
                'notes': auth.notes,
            }
            
            if request.user.is_staff or request.user.is_superuser:
                auth_data['user'] = {
                    'id': str(auth.user.id),
                    'username': auth.user.username,
                    'email': auth.user.email,
                } if auth.user else None
            
            if auth.expires_at:
                auth_data['expires_at'] = auth.expires_at.isoformat()
            
            if auth.verified_at:
                auth_data['verified_at'] = auth.verified_at.isoformat()
            
            if auth.approved_by:
                auth_data['approved_by'] = {
                    'id': str(auth.approved_by.id),
                    'username': auth.approved_by.username,
                }
                auth_data['approved_by_username'] = auth.approved_by.username
            
            return Response(auth_data)
        
        elif request.method == 'DELETE':
            if auth.status == 'pending' or request.user.is_staff or request.user.is_superuser:
                auth.delete()
                return Response({'message': 'Domain authorization deleted'})
            else:
                return Response(
                    {'error': 'Cannot delete verified authorization'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        elif request.method == 'PATCH':
            data = request.data
            if 'notes' in data:
                auth.notes = data['notes']
            
            auth.save()
            return Response({'message': 'Domain authorization updated'})
            
    except DomainAuthorization.DoesNotExist:
        return Response({'error': 'Authorization not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error accessing domain authorization {auth_id}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_domain_authorization(request, auth_id):
    """Approve a domain authorization (admin/superuser only)"""
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({'error': 'Permission denied. Admin privileges required.'}, status=status.HTTP_403_FORBIDDEN)
    
    try:
        auth = DomainAuthorization.objects.get(id=auth_id)
        
        if auth.status == 'verified':
            return Response({
                'message': f'Domain authorization for {auth.domain} is already approved',
                'status': 'verified'
            })
        
        auth.status = 'verified'
        auth.verified_at = timezone.now()
        auth.approved_by = request.user
        auth.expires_at = timezone.now() + timezone.timedelta(days=365)
        
        auth.save()
        
        logger.info(f"Admin {request.user.username} approved domain authorization {auth_id} for {auth.domain}")
        
        return Response({
            'message': f'Domain authorization for {auth.domain} has been approved',
            'id': str(auth.id),
            'domain': auth.domain,
            'is_verified': True,
            'is_approved': True,
            'status': auth.status,
            'verified_at': auth.verified_at.isoformat(),
            'expires_at': auth.expires_at.isoformat(),
            'approved_by': auth.approved_by.username,
        })
        
    except DomainAuthorization.DoesNotExist:
        return Response({'error': 'Authorization not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error approving domain authorization {auth_id}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_domain_authorization(request, auth_id):
    """Revoke a domain authorization (own authorizations or admin)"""
    try:
        if request.user.is_staff or request.user.is_superuser:
            auth = DomainAuthorization.objects.get(id=auth_id)
        else:
            auth = DomainAuthorization.objects.get(id=auth_id, user=request.user)
        
        auth.status = 'rejected'
        auth.save()
        
        logger.info(f"User {request.user.username} revoked domain authorization {auth_id} for {auth.domain}")
        
        return Response({
            'message': f'Domain authorization for {auth.domain} has been revoked',
            'id': str(auth.id),
            'domain': auth.domain,
            'status': auth.status,
            'is_active': auth.is_active,
        })
        
    except DomainAuthorization.DoesNotExist:
        return Response({'error': 'Authorization not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error revoking domain authorization {auth_id}: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_list_all_domain_authorizations(request):
    """List ALL domain authorizations for admin users - ADMIN ONLY"""
    
    if not (request.user.is_staff or request.user.is_superuser):
        return Response(
            {'error': 'Permission denied. Admin privileges required.'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        authorizations = DomainAuthorization.objects.all().select_related('user', 'approved_by').order_by('-requested_at')
        
        results = []
        for auth in authorizations:
            auth_data = {
                'id': str(auth.id),
                'domain': auth.domain,
                'verification_method': auth.verification_method,
                'status': auth.status,
                'is_verified': auth.status == 'verified',
                'is_approved': auth.status == 'verified',
                'is_active': auth.is_active,
                'created_at': auth.requested_at.isoformat(),
                'requested_at': auth.requested_at.isoformat(),
                'verification_token': auth.verification_token,
                'verification_data': auth.verification_data,
                'notes': auth.notes,
                
                'user': {
                    'id': str(auth.user.id),
                    'username': auth.user.username,
                    'email': auth.user.email,
                    'first_name': auth.user.first_name,
                    'last_name': auth.user.last_name,
                } if auth.user else None,
                
                'contact_person': getattr(auth, 'contact_person', ''),
                'contact_email': getattr(auth, 'contact_email', ''),
            }
            
            if auth.expires_at:
                auth_data['expires_at'] = auth.expires_at.isoformat()
                auth_data['valid_until'] = auth.expires_at.isoformat()
            
            if auth.verified_at:
                auth_data['verified_at'] = auth.verified_at.isoformat()
            
            if auth.approved_by:
                auth_data['approved_by'] = {
                    'id': str(auth.approved_by.id),
                    'username': auth.approved_by.username,
                }
                auth_data['approved_by_username'] = auth.approved_by.username
                auth_data['approved_at'] = auth.verified_at.isoformat() if auth.verified_at else None
            
            results.append(auth_data)
        
        return Response({
            'count': len(results),
            'results': results,
            'is_admin_view': True,
        })
        
    except Exception as e:
        logger.error(f"Error listing all domain authorizations for admin: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ========== COMPLIANCE VIEWSET ==========

class ComplianceViewSet(viewsets.ViewSet):
    """Complete compliance management viewset"""
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['get'])
    def status(self, request):
        """Get user's compliance status"""
        return compliance_status(request)
    
    @action(detail=False, methods=['post'])
    def accept_agreement(self, request):
        """Accept a legal agreement"""
        return accept_agreement(request)
    
    @action(detail=False, methods=['post'])
    def check_url(self, request):
        """Check URL authorization"""
        return check_url_authorization(request)
    
    @action(detail=False, methods=['get'])
    def scan_modes(self, request):
        """Get scan mode information"""
        return scan_modes(request)
    
    @action(detail=False, methods=['get'])
    def legal_notices(self, request):
        """Get legal notices"""
        return legal_notices(request)
    
    @action(detail=False, methods=['post'])
    def request_domain(self, request):
        """Request domain authorization"""
        return request_domain_authorization(request)
    
    @action(detail=False, methods=['post'])
    def verify_domain(self, request):
        """Verify domain authorization"""
        return verify_domain_authorization(request)
    
    @action(detail=False, methods=['get'])
    def domains(self, request):
        """List domain authorizations"""
        return list_domain_authorizations(request)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAdminUser])
    def admin_domains(self, request):
        """List all domain authorizations (admin only)"""
        return admin_list_all_domain_authorizations(request)

# ========== PREAUTHORIZED DOMAINS ==========

@api_view(['GET'])
def list_preauthorized_domains(request):
    """List pre-authorized test domains (public endpoint)"""
    try:
        domains = PreauthorizedDomain.objects.filter(is_active=True).order_by('domain')
        
        results = []
        for domain in domains:
            results.append({
                'domain': domain.domain,
                'description': domain.description,
                'is_active': domain.is_active
            })
        
        return Response({
            'count': len(results),
            'results': results,
            'note': 'These domains are pre-authorized for testing and learning purposes'
        })
        
    except Exception as e:
        logger.error(f"Error listing preauthorized domains: {e}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ========== UTILITY FUNCTIONS ==========

def _get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip