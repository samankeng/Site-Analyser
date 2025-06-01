# server/site_analyser/settings/security_compliance.py - Updated with domain authorization

"""
Security Scanner Legal Compliance Settings with Domain Authorization Support
"""

# ========== LEGAL COMPLIANCE SETTINGS ==========

# Enable security audit logging
SECURITY_AUDIT_LOG = True

# Pre-authorized test domains (don't require user verification)
SCANNER_PREAUTHORIZED_DOMAINS = [
    'badssl.com',
    'testphp.vulnweb.com', 
    'demo.testfire.net',
    'httpbin.org',
    'localhost',
    '127.0.0.1',
    'reqbin.com',
    'example.com',
    'iana.org'
]

# Domain authorization settings
DOMAIN_AUTHORIZATION = {
    'verification_methods': ['dns_txt', 'file_upload', 'email_verification', 'manual_approval'],
    'default_expiry_days': 365,
    'max_domains_per_user': 10,
    'auto_approve_subdomains': True,  # If user owns example.com, auto-approve *.example.com
    'require_admin_approval': False,  # Set to True for manual approval workflow
}

# DNS verification settings
DNS_VERIFICATION = {
    'txt_record_prefix': 'site-analyser-verify',
    'verification_timeout': 300,  # 5 minutes
    'max_verification_attempts': 3,
}

# File verification settings  
FILE_VERIFICATION = {
    'file_prefix': 'site-analyser',
    'allowed_extensions': ['.txt', '.html'],
    'max_file_size': 1024,  # 1KB
    'verification_timeout': 300,  # 5 minutes
}

# Default compliance mode for new scans
DEFAULT_SCANNER_COMPLIANCE_MODE = 'strict'  # 'strict', 'moderate', 'permissive'

# Terms of Service acceptance required
SCANNER_REQUIRE_TOS_ACCEPTANCE = True

# User agreement and legal notices
SCANNER_LEGAL_NOTICES = {
    'terms_of_service': {
        'title': 'Security Scanner Terms of Service',
        'content': '''
        BY USING THIS SECURITY SCANNER, YOU AGREE TO THE FOLLOWING TERMS:

        1. AUTHORIZED USE ONLY
           - You may only scan websites that you own or have explicit written permission to test
           - Unauthorized scanning of third-party websites is strictly prohibited
           - You are solely responsible for obtaining proper authorization

        2. LEGAL COMPLIANCE
           - You must comply with all applicable local, state, and federal laws
           - You must respect the Computer Fraud and Abuse Act (CFAA) and similar laws
           - International users must comply with their local cybersecurity laws

        3. ETHICAL SCANNING
           - Use results responsibly and for legitimate security purposes only
           - Follow responsible disclosure practices for any vulnerabilities found
           - Do not use findings for malicious purposes

        4. LIMITATIONS
           - This tool is provided "as-is" without warranties
           - Results may contain false positives and should be manually verified
           - The scanner is not a substitute for professional security assessment

        5. LIABILITY
           - You assume all responsibility for the use of this scanner
           - You agree to indemnify the service provider against any claims
           - Misuse of this tool may result in legal consequences

        By proceeding, you acknowledge that you have read, understood, and agree to these terms.
        ''',
        'version': '1.0',
        'effective_date': '2024-01-01'
    },
    
    'privacy_policy': {
        'title': 'Security Scanner Privacy Policy',
        'content': '''
        PRIVACY POLICY FOR SECURITY SCANNER

        1. DATA COLLECTION
           - We log scan activities for security and compliance purposes
           - IP addresses, timestamps, and scan targets are recorded
           - User account information is stored securely
           - Domain authorization data is stored for verification

        2. DATA USE
           - Audit logs are used for security monitoring and legal compliance
           - Scan results are stored temporarily and associated with your account
           - Data may be reviewed in case of suspected misuse
           - Domain ownership verification is used to authorize active scanning

        3. DATA SHARING
           - We do not sell or share your data with third parties
           - Data may be disclosed if required by law or legal process
           - Suspected illegal activity may be reported to authorities

        4. DATA RETENTION
           - Scan results are retained for 90 days unless deleted by user
           - Audit logs are retained for 1 year for compliance purposes
           - Account data is retained while account is active
           - Domain authorizations expire after 1 year

        5. YOUR RIGHTS
           - You can delete your scan history at any time
           - You can revoke domain authorizations at any time
           - You can request account deletion (subject to legal retention requirements)
           - You can contact us regarding privacy concerns

        Contact: privacy@yourcompany.com
        ''',
        'version': '1.0',
        'effective_date': '2024-01-01'
    },
    
    'responsible_disclosure': {
        'title': 'Responsible Disclosure Guidelines',
        'content': '''
        RESPONSIBLE DISCLOSURE GUIDELINES

        If you discover vulnerabilities using this scanner:

        1. DO NOT exploit vulnerabilities beyond what is necessary to demonstrate the issue
        2. DO NOT access, modify, or delete data belonging to others
        3. DO NOT perform actions that could harm the target system or its users
        4. DO contact the affected organization privately before public disclosure
        5. DO allow reasonable time for the organization to address the issue
        6. DO follow coordinated disclosure practices

        REPORTING PROCESS:
        1. Document the vulnerability clearly and completely
        2. Contact the organization's security team or designated contact
        3. Provide clear reproduction steps and impact assessment
        4. Allow 90 days for resolution before considering public disclosure
        5. Work cooperatively with the organization to resolve the issue

        PROHIBITED ACTIONS:
        - Public disclosure without prior coordination
        - Selling vulnerability information
        - Using vulnerabilities for unauthorized access
        - Causing service disruption or data loss
        - Violating privacy or confidentiality

        Remember: The goal is to improve security, not to cause harm.
        ''',
        'version': '1.0',
        'effective_date': '2024-01-01'
    },
    
    'active_scanning': {
        'title': 'Active Scanning Legal Agreement',
        'content': '''
        ACTIVE SCANNING LEGAL AGREEMENT

        By accepting this agreement, you acknowledge and agree to the following:

        1. LEGAL AUTHORIZATION REQUIRED
           - Active scanning involves intrusive testing that may trigger security alerts
           - You must have explicit written authorization to test the target systems
           - You are solely responsible for ensuring you have proper authorization
           - Unauthorized active scanning may violate computer crime laws

        2. DOMAIN OWNERSHIP VERIFICATION
           - You must verify ownership of domains before active scanning
           - Verification methods include DNS TXT records or file uploads
           - Pre-authorized test domains (like badssl.com) don't require verification
           - Active scanning is disabled for unverified domains

        3. TECHNICAL RESPONSIBILITIES
           - Active scans may impact system performance
           - You should inform system administrators before scanning
           - You should scan during appropriate maintenance windows
           - You should monitor scan impact and stop if issues arise

        4. LEGAL COMPLIANCE
           - You must comply with all applicable cybersecurity laws
           - You must respect the Computer Fraud and Abuse Act (CFAA)
           - International users must comply with local laws (e.g., UK Computer Misuse Act)
           - You must follow your organization's security testing policies

        5. ETHICAL OBLIGATIONS
           - Use active scanning only for legitimate security purposes
           - Do not use active scanning to gain unauthorized access
           - Report vulnerabilities through responsible disclosure
           - Do not cause unnecessary disruption to target systems

        6. LIABILITY AND INDEMNIFICATION
           - You assume full responsibility for active scanning activities
           - You agree to indemnify the service provider against any claims
           - You understand that misuse may result in legal consequences
           - The service provider is not liable for your scanning activities

        By accepting this agreement, you confirm that you understand the legal and
        technical implications of active security scanning and agree to use this
        capability responsibly and in compliance with all applicable laws.
        ''',
        'version': '1.0',
        'effective_date': '2024-01-01'
    }
}

# Rate limiting settings (enhanced for domain-based limits)
SCANNER_RATE_LIMITS = {
    'requests_per_minute': 30,
    'scans_per_hour': 5,
    'scans_per_day': 20,
    'max_concurrent_scans': 2,
    'max_active_scans_per_day': 5,  # Stricter limit for active scans
    'domain_scan_cooldown': 300,  # 5 minutes between scans of same domain
}

# Compliance mode restrictions (updated for active scanning)
SCANNER_COMPLIANCE_RESTRICTIONS = {
    'strict': {
        'max_pages': 5,
        'max_requests': 50,
        'request_delay': 2.0,
        'max_payloads': 3,
        'allowed_tests': ['passive_only'],
        'require_permission_confirmation': True,
        'require_domain_authorization': True,  # Always require for active
    },
    'moderate': {
        'max_pages': 10,
        'max_requests': 100,
        'request_delay': 1.0,
        'max_payloads': 6,
        'allowed_tests': ['passive', 'safe_active'],
        'require_permission_confirmation': True,
        'require_domain_authorization': True,
    },
    'permissive': {
        'max_pages': 20,
        'max_requests': 200,
        'request_delay': 0.5,
        'max_payloads': 12,
        'allowed_tests': ['passive', 'safe_active', 'limited_active'],
        'require_permission_confirmation': True,
        'require_domain_authorization': True,
        'require_admin_approval': True  # Requires admin approval for permissive mode
    }
}

# Logging configuration for compliance (enhanced for domain authorization)
LOGGING_COMPLIANCE = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'compliance': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'security_audit': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/security_audit.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'compliance',
        },
        'domain_authorization': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logs/domain_authorization.log',
            'maxBytes': 5242880,  # 5MB
            'backupCount': 5,
            'formatter': 'compliance',
        },
        'compliance_console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'compliance',
        },
    },
    'loggers': {
        'scanner.compliance': {
            'handlers': ['security_audit', 'compliance_console'],
            'level': 'INFO',
            'propagate': False,
        },
        'compliance.domain_auth': {
            'handlers': ['domain_authorization', 'compliance_console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Email notifications for compliance violations (enhanced)
COMPLIANCE_NOTIFICATIONS = {
    'enabled': True,
    'admin_email': 'security-admin@yourcompany.com',
    'notify_on': [
        'compliance_violation',
        'unauthorized_scan_attempt',
        'rate_limit_exceeded',
        'suspicious_activity',
        'domain_authorization_requested',  # New
        'domain_verification_failed',      # New
        'active_scan_without_authorization' # New
    ]
}

# Legal contact information
LEGAL_CONTACT_INFO = {
    'company_name': 'Your Company Name',
    'legal_department': 'legal@yourcompany.com',
    'security_team': 'security@yourcompany.com',
    'abuse_contact': 'abuse@yourcompany.com',
    'phone': '+1-555-0123',
    'address': '123 Security Street, Cyber City, CC 12345'
}

# Disclaimer and warnings (enhanced for domain authorization)
SCANNER_DISCLAIMERS = {
    'general_warning': 'This tool performs active security testing. Use only on authorized systems.',
    'legal_warning': 'Unauthorized use may violate computer crime laws.',
    'accuracy_disclaimer': 'Results should be manually verified. False positives may occur.',
    'professional_disclaimer': 'This tool does not replace professional security assessments.',
    'domain_authorization_warning': 'Active scanning requires domain ownership verification.',
    'test_domain_notice': 'Pre-authorized test domains available for learning and testing.'
}