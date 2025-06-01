# backend/scanner/management/commands/setup_admin.py
# Create this file to set up admin user and initial data

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from scanner.models import UserAgreement, ScanAuthorization

User = get_user_model()

class Command(BaseCommand):
    help = 'Set up admin user and initial compliance data'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Admin email address',
            default='admin@example.com'
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Admin password',
            default='admin123'
        )
        parser.add_argument(
            '--skip-agreements',
            action='store_true',
            help='Skip creating sample agreements'
        )
    
    def handle(self, *args, **options):
        email = options['email']
        password = options['password']
        
        # Create superuser
        if not User.objects.filter(email=email).exists():
            admin_user = User.objects.create_superuser(
                email=email,
                password=password,
                username='admin',
                first_name='Admin',
                last_name='User'
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'✓ Created admin user: {email}')
            )
            
            # Create sample agreements for admin user
            if not options['skip_agreements']:
                self.create_sample_agreements(admin_user)
            
        else:
            admin_user = User.objects.get(email=email)
            self.stdout.write(
                self.style.WARNING(f'⚠ Admin user already exists: {email}')
            )
        
        # Create a regular test user
        if not User.objects.filter(email='user@example.com').exists():
            test_user = User.objects.create_user(
                email='user@example.com',
                password='user123',
                username='testuser',
                first_name='Test',
                last_name='User'
            )
            
            self.stdout.write(
                self.style.SUCCESS('✓ Created test user: user@example.com')
            )
            
            # Create sample agreements for test user
            if not options['skip_agreements']:
                self.create_sample_agreements(test_user)
        
        self.stdout.write(
            self.style.SUCCESS('\n🎉 Admin setup complete!')
        )
        self.stdout.write('Access the admin panel at: /admin/')
        self.stdout.write('Access the API admin panel at: /admin/authorizations')
        self.stdout.write(f'Login with: {email} / {password}')
    
    def create_sample_agreements(self, user):
        """Create sample user agreements"""
        agreements = [
            'terms_of_service',
            'privacy_policy', 
            'responsible_disclosure',
            'active_scanning_agreement'
        ]
        
        created_count = 0
        for agreement_type in agreements:
            if not UserAgreement.objects.filter(
                user=user, 
                agreement_type=agreement_type
            ).exists():
                UserAgreement.objects.create(
                    user=user,
                    agreement_type=agreement_type,
                    agreement_version='1.0',
                    ip_address='127.0.0.1',
                    user_agent='Django Management Command'
                )
                created_count += 1
        
        if created_count > 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f'✓ Created {created_count} sample agreements for {user.username}'
                )
            )
        
        # Create sample authorization for test domains
        if user.username != 'admin':  # Only for non-admin users
            test_domains = [
                'badssl.com',
                'testphp.vulnweb.com', 
                'demo.testfire.net'
            ]
            
            for domain in test_domains:
                if not ScanAuthorization.objects.filter(
                    user=user, 
                    domain=domain
                ).exists():
                    ScanAuthorization.objects.create(
                        user=user,
                        domain=domain,
                        authorization_type='self_owned',
                        compliance_mode='moderate',
                        authorization_notes=f'Sample authorization for testing domain {domain}',
                        contact_person=f'{user.first_name} {user.last_name}',
                        contact_email=user.email,
                        is_approved=True,
                        approved_by=None,  # Will be set to admin later
                        approved_at=timezone.now(),
                        valid_from=timezone.now(),
                        valid_until=timezone.now() + timedelta(days=365),
                        is_active=True
                    )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'✓ Created sample authorizations for {user.username}'
                )
            )