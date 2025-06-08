# backend/scanner/serializers.py - Updated to remove database report references

from rest_framework import serializers
from .models import (
    Scan, ScanResult, SecurityAuditLog, ComplianceReport
)


class ScanResultSerializer(serializers.ModelSerializer):
    """Serializer for scan result objects"""
    
    class Meta:
        model = ScanResult
        fields = ('id', 'category', 'name', 'description', 'severity', 'details', 'created_at')
        read_only_fields = ('id', 'created_at')

class ScanSerializer(serializers.ModelSerializer):
    """Enhanced scan serializer with compliance information and scan mode support"""
    
    results = ScanResultSerializer(many=True, read_only=True)
    compliance_status = serializers.SerializerMethodField()
    authorization_info = serializers.SerializerMethodField()
    legal_compliance = serializers.SerializerMethodField()
    scan_mode_info = serializers.SerializerMethodField()
    pdf_report_available = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = (
            'id', 'target_url', 'scan_types', 'scan_mode', 'status', 'created_at',
            'updated_at', 'started_at', 'completed_at', 'error_message',
            'compliance_mode', 'terms_accepted', 'terms_accepted_at',
            'authorization_required', 'requests_made', 'pages_scanned', 
            'compliance_violations', 'results', 'compliance_status', 
            'authorization_info', 'legal_compliance', 'scan_mode_info',
            'pdf_report_available'
        )
        read_only_fields = (
            'id', 'status', 'created_at', 'updated_at', 'started_at',
            'completed_at', 'error_message', 'requests_made', 'pages_scanned',
            'compliance_violations', 'compliance_status', 'authorization_info',
            'legal_compliance', 'scan_mode_info', 'authorization_required',
            'pdf_report_available'
        )
    
    def get_compliance_status(self, obj):
        """Get compliance status for the scan"""
        try:
            # Use compliance service for status check
            from compliance.services.compliance_service import ComplianceService
            service = ComplianceService(obj.user)
            
            violations = getattr(obj, 'compliance_violations', [])
            
            return {
                'compliant': len(violations) == 0,
                'violations_count': len(violations),
                'compliance_mode': getattr(obj, 'compliance_mode', 'strict'),
                'scan_mode': getattr(obj, 'scan_mode', 'passive'),
                'terms_accepted': getattr(obj, 'terms_accepted', False),
                'authorization_required': obj.requires_authorization() if hasattr(obj, 'requires_authorization') else False,
                'authorization_valid': obj.is_authorized() if hasattr(obj, 'is_authorized') else True
            }
        except (ImportError, AttributeError):
            # Fallback for development
            return {
                'compliant': True,
                'violations_count': 0,
                'compliance_mode': 'strict',
                'scan_mode': getattr(obj, 'scan_mode', 'passive'),
                'terms_accepted': True,
                'authorization_required': False,
                'authorization_valid': True
            }
    
    def get_authorization_info(self, obj):
        """Get authorization information for the scan"""
        try:
            if hasattr(obj, 'authorization') and obj.authorization:
                return {
                    'id': str(obj.authorization.id),
                    'verification_method': getattr(obj.authorization, 'verification_method', 'unknown'),
                    'status': getattr(obj.authorization, 'status', 'unknown'),
                    'verified_at': getattr(obj.authorization, 'verified_at', None),
                    'expires_at': getattr(obj.authorization, 'expires_at', None),
                    'is_valid': obj.authorization.is_valid() if hasattr(obj.authorization, 'is_valid') else False,
                }
        except AttributeError:
            pass
        return None
    
    def get_legal_compliance(self, obj):
        """Get legal compliance information"""
        from urllib.parse import urlparse
        
        domain = urlparse(obj.target_url).netloc
        
        return {
            'domain': domain,
            'scan_mode': getattr(obj, 'scan_mode', 'passive'),
            'terms_accepted': getattr(obj, 'terms_accepted', True),
            'terms_accepted_at': getattr(obj, 'terms_accepted_at', None),
            'authorized': hasattr(obj, 'authorization') and obj.authorization is not None,
            'authorization_required': obj.requires_authorization() if hasattr(obj, 'requires_authorization') else False,
            'compliance_score': self._calculate_compliance_score(obj)
        }
    
    def get_scan_mode_info(self, obj):
        """Get scan mode specific information"""
        scan_mode = getattr(obj, 'scan_mode', 'passive')
        
        mode_info = {
            'passive': {
                'name': 'Passive Scan',
                'description': 'Safe, non-intrusive analysis',
                'risk_level': 'Very Low',
                'authorization_required': False
            },
            'active': {
                'name': 'Active Scan',
                'description': 'Intrusive vulnerability testing',
                'risk_level': 'High',
                'authorization_required': True
            },
            'mixed': {
                'name': 'Mixed Scan',
                'description': 'Combination of passive and active testing',
                'risk_level': 'Medium',
                'authorization_required': 'Conditional'
            }
        }
        
        return {
            'mode': scan_mode,
            'info': mode_info.get(scan_mode, mode_info['passive']),
            'is_authorized': obj.is_authorized() if hasattr(obj, 'is_authorized') else True,
            'requires_authorization': obj.requires_authorization() if hasattr(obj, 'requires_authorization') else False
        }
    
    def get_pdf_report_available(self, obj):
        """Check if PDF report can be generated for this scan"""
        return obj.status == 'completed'
    
    def _calculate_compliance_score(self, obj):
        """Calculate compliance score for scan"""
        score = 50
        
        # Deduct for violations
        violations = getattr(obj, 'compliance_violations', [])
        score -= len(violations) * 10
        
        # Deduct based on scan mode authorization requirements
        scan_mode = getattr(obj, 'scan_mode', 'passive')
        if scan_mode in ['active', 'mixed']:
            if hasattr(obj, 'requires_authorization') and obj.requires_authorization():
                if hasattr(obj, 'is_authorized') and obj.is_authorized():
                    score += 30
        
        # Deduct if terms not accepted
        if not getattr(obj, 'terms_accepted', True):
            score -= 20
        
        return max(0, score)

class ScanCreateSerializer(serializers.ModelSerializer):
    """Enhanced scan creation serializer with scan mode and compliance checks"""
    
    scan_mode = serializers.ChoiceField(
        choices=[('passive', 'Passive'), ('active', 'Active'), ('mixed', 'Mixed')],
        default='passive',
        required=False,
        help_text='Type of scan to perform'
    )
    
    compliance_mode = serializers.ChoiceField(
        choices=[('strict', 'Strict'), ('moderate', 'Moderate'), ('permissive', 'Permissive')],
        default='strict',
        required=False,
        help_text='Compliance level for the scan'
    )
    
    class Meta:
        model = Scan
        fields = ('target_url', 'scan_types', 'scan_mode', 'compliance_mode')
    
    def validate(self, data):
        """Validate scan creation with scan mode and compliance checks"""
        from urllib.parse import urlparse
        
        target_url = data['target_url']
        scan_mode = data.get('scan_mode', 'passive')
        domain = urlparse(target_url).netloc
        
        # Use compliance service for validation
        try:
            from compliance.services.compliance_service import ComplianceService
            
            user = self.context['request'].user
            compliance_service = ComplianceService(user)
            
            # Check if user can perform this type of scan on this domain
            can_scan, reason = compliance_service.can_scan_domain(target_url, scan_mode)
            if not can_scan:
                raise serializers.ValidationError({
                    'scan_mode': f"Cannot perform {scan_mode} scan: {reason}",
                    'domain': domain,
                    'required_agreements': compliance_service.get_missing_agreements()
                })
            
        except ImportError:
            # If compliance service doesn't exist yet, just warn
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Compliance service not available - allowing {scan_mode} scan of {domain}")
        
        return data
    
    def create(self, validated_data):
        """Create scan with scan mode and compliance tracking"""
        from django.utils import timezone
        from urllib.parse import urlparse
        
        user = self.context['request'].user
        target_url = validated_data['target_url']
        scan_mode = validated_data.get('scan_mode', 'passive')
        domain = urlparse(target_url).netloc
        
        # Use compliance service to get authorization
        try:
            from compliance.services.compliance_service import ComplianceService
            compliance_service = ComplianceService(user)
            
            # Check if it's pre-authorized
            is_preauth = compliance_service.is_preauthorized_domain(target_url)
            
            # Get authorization for active/mixed scans
            authorization = None
            authorization_required = False
            
            if scan_mode in ['active', 'mixed'] and not is_preauth:
                authorization_required = True
                authorization = compliance_service.get_domain_authorization(domain)
            
            # Set compliance mode
            if is_preauth:
                compliance_mode = 'permissive'
            elif scan_mode == 'passive':
                compliance_mode = validated_data.get('compliance_mode', 'strict')
            else:
                compliance_mode = validated_data.get('compliance_mode', 'moderate')
            
        except ImportError:
            # Fallback if compliance service not available
            authorization = None
            authorization_required = False
            compliance_mode = validated_data.get('compliance_mode', 'strict')
        
        # Create scan with enhanced data
        scan_data = {
            'user': user,
            'scan_mode': scan_mode,
            'compliance_mode': compliance_mode,
            'authorization_required': authorization_required,
            'terms_accepted': True,
            'terms_accepted_at': timezone.now(),
            **validated_data
        }
        
        # Add authorization if available
        if authorization:
            scan_data['authorization'] = authorization
        
        # Add IP address if available
        request = self.context.get('request')
        if request:
            scan_data['terms_ip_address'] = self._get_client_ip(request)
        
        scan = Scan.objects.create(**scan_data)
        return scan
    
    def _get_client_ip(self, request):
        """Get client IP from request context"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR', '')

class SecurityAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for security audit logs with scan mode support"""
    
    user_username = serializers.CharField(source='user.username', read_only=True)
    reviewed_by_username = serializers.CharField(source='reviewed_by.username', read_only=True)
    
    class Meta:
        model = SecurityAuditLog
        fields = (
            'id', 'event_type', 'severity', 'timestamp', 'user_username',
            'ip_address', 'user_agent', 'target_domain', 'scan_id',
            'scan_mode', 'compliance_mode', 'event_data', 'message', 'reviewed',
            'reviewed_by_username', 'reviewed_at'
        )
        read_only_fields = (
            'id', 'timestamp', 'user_username', 'reviewed_by_username'
        )

class ComplianceStatusSerializer(serializers.Serializer):
    """Serializer for user compliance status with scan mode capabilities"""
    
    user_id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    compliance_score = serializers.IntegerField(read_only=True)
    agreements = serializers.DictField(read_only=True)
    authorizations = serializers.DictField(read_only=True)
    scanning_activity = serializers.DictField(read_only=True)
    rate_limits = serializers.DictField(read_only=True)
    recommendations = serializers.ListField(read_only=True)
    scan_capabilities = serializers.DictField(read_only=True)

class ScanModeInfoSerializer(serializers.Serializer):
    """Serializer for scan mode information"""
    
    name = serializers.CharField()
    description = serializers.CharField()
    requirements = serializers.ListField(child=serializers.CharField())
    capabilities = serializers.ListField(child=serializers.CharField())
    authorization_required = serializers.BooleanField()
    legal_risk = serializers.CharField()
    recommended_for = serializers.CharField()

class ComplianceReportSerializer(serializers.ModelSerializer):
    """Serializer for compliance reports"""
    
    generated_by_username = serializers.CharField(source='generated_by.username', read_only=True)
    
    class Meta:
        model = ComplianceReport
        fields = (
            'id', 'report_type', 'generated_at', 'generated_by_username',
            'period_start', 'period_end', 'report_data', 'summary'
        )
        read_only_fields = (
            'id', 'generated_at', 'generated_by_username'
        )