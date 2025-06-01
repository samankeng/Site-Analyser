# compliance/urls.py - FIXED VERSION (removed test_view)

from django.urls import path
from . import views

urlpatterns = [
    # Compliance status and agreements
    path('status/', views.compliance_status, name='compliance_status'),
    path('accept/', views.accept_agreement, name='accept_agreement'),
    path('check-url/', views.check_url_authorization, name='check_url_authorization'),
    path('scan-modes/', views.scan_modes, name='scan_modes'),
    
    # Domain authorization endpoints - using int instead of uuid
    path('request-domain/', views.request_domain_authorization, name='request_domain_authorization'),
    path('verify-domain/', views.verify_domain_authorization, name='verify_domain_authorization'),
    path('domain-authorizations/', views.list_domain_authorizations, name='list_domain_authorizations'),
    path('domain-authorizations/<int:auth_id>/', views.domain_authorization_detail, name='domain_authorization_detail'),
    path('domain-authorizations/<int:auth_id>/approve/', views.approve_domain_authorization, name='approve_domain_authorization'),
    path('domain-authorizations/<int:auth_id>/revoke/', views.revoke_domain_authorization, name='revoke_domain_authorization'),
    
    # Admin endpoints for managing all domain authorizations
    path('admin/domain-authorizations/', views.admin_list_all_domain_authorizations, name='admin_list_all_domain_authorizations'),
    
    
]