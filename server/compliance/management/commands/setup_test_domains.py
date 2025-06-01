# compliance/management/commands/setup_test_domains.py

from django.core.management.base import BaseCommand
from compliance.models import PreauthorizedDomain

class Command(BaseCommand):
    help = 'Set up pre-authorized test domains for security scanning'

    def handle(self, *args, **options):
        test_domains = [
            ('badssl.com', 'BadSSL - SSL/TLS testing site with various broken configurations'),
            ('self-signed.badssl.com', 'Self-signed certificate test'),
            ('wrong.host.badssl.com', 'Wrong hostname certificate test'),
            ('expired.badssl.com', 'Expired certificate test'),
            ('revoked.badssl.com', 'Revoked certificate test'),
            ('pinning-test.badssl.com', 'Certificate pinning test'),
            ('no-common-name.badssl.com', 'No common name certificate test'),
            ('no-subject.badssl.com', 'No subject certificate test'),
            ('incomplete-chain.badssl.com', 'Incomplete certificate chain test'),
            ('sha1-intermediate.badssl.com', 'SHA-1 intermediate certificate test'),
            ('httpbin.org', 'HTTP testing service for API testing'),
            ('jsonplaceholder.typicode.com', 'JSON placeholder API for testing'),
            ('postman-echo.com', 'Postman echo service for HTTP testing'),
            ('example.com', 'IANA example domain for testing'),
            ('test.com', 'Test domain (if used for testing)'),
            ('localhost', 'Local development domain'),
            ('127.0.0.1', 'Local loopback IP'),
        ]

        created_count = 0
        updated_count = 0

        for domain, description in test_domains:
            obj, created = PreauthorizedDomain.objects.get_or_create(
                domain=domain,
                defaults={
                    'description': description,
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Created pre-authorized domain: {domain}')
                )
            else:
                # Update description if it's different
                if obj.description != description:
                    obj.description = description
                    obj.save()
                    updated_count += 1
                    self.stdout.write(
                        self.style.WARNING(f'→ Updated description for: {domain}')
                    )
                else:
                    self.stdout.write(f'  Already exists: {domain}')

        self.stdout.write(
            self.style.SUCCESS(
                f'\nSummary: {created_count} domains created, {updated_count} updated'
            )
        )
        
        # List all active pre-authorized domains
        active_domains = PreauthorizedDomain.objects.filter(is_active=True).order_by('domain')
        self.stdout.write(f'\nActive pre-authorized domains ({active_domains.count()}):')
        for domain in active_domains:
            self.stdout.write(f'  • {domain.domain} - {domain.description}')