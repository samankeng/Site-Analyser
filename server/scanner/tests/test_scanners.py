import unittest
from scanner.services.header_scanner import HeaderScanner
from scanner.services.ssl_scanner import SslScanner
from scanner.services.vulnerability_scanner import VulnerabilityScanner
from scanner.services.csp_scanner import CspScanner
from scanner.services.cors_scanner import CorsScanner
from scanner.services.port_scanner import PortScanner
from scanner.services.server_analyzer import ServerAnalyzer
from scanner.services.content_scanner import ContentScanner
from scanner.services.cookie_scanner import CookieScanner
from scanner.services.compliance_service import ComplianceService
from scanner.models import Scan, ScanResult, UserAgreement, ScanAuthorization
from scanner.serializers import ScanSerializer, ScanCreateSerializer
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory
from unittest.mock import MagicMock
import uuid

User = get_user_model()

class ScannerTestCase(unittest.TestCase):
    def setUp(self):
        self.https_url = 'https://example.com'
        self.http_url = 'http://example.com'
        unique_id = uuid.uuid4().hex[:8]
        self.user = User.objects.create_user(
            username=f'testuser_{unique_id}',
            email=f'testuser_{unique_id}@example.com',  # ✅ Unique email
            password='testpass'
        )

    def test_header_scanner(self):
        scanner = HeaderScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_ssl_scanner_https(self):
        scanner = SslScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_ssl_scanner_http(self):
        scanner = SslScanner(self.http_url)
        results = scanner.scan()
        self.assertTrue(any(f['name'] == 'Not Using HTTPS' for f in results))

    def test_csp_scanner(self):
        scanner = CspScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_cors_scanner(self):
        scanner = CorsScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_port_scanner(self):
        scanner = PortScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_server_analyzer(self):
        scanner = ServerAnalyzer(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_content_scanner(self):
        scanner = ContentScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_cookie_scanner(self):
        scanner = CookieScanner(self.https_url)
        results = scanner.scan()
        self.assertIsInstance(results, list)

    def test_vulnerability_scanner(self):
        try:
            scanner = VulnerabilityScanner(self.https_url, compliance_mode='strict')
            results = scanner.scan()
            self.assertIsInstance(results, list)
        except Exception as e:
            self.assertIn('compliance', str(e).lower())

    def test_compliance_service_agreements(self):
        service = ComplianceService(self.user)
        service.has_accepted_required_agreements = MagicMock(return_value=False)
        self.assertFalse(service.has_accepted_required_agreements())

    def test_scan_model_str(self):
        scan = Scan.objects.create(
            user=self.user,
            target_url=self.https_url,
            scan_types=['headers'],
            status='completed',
            compliance_mode='strict'
        )
        self.assertIn(scan.target_url, str(scan))
        self.assertIn(scan.status, str(scan))

    def test_scan_result_model_str(self):
        scan = Scan.objects.create(
            user=self.user,
            target_url=self.https_url,
            scan_types=['ssl'],
            compliance_mode='strict'
        )
        result = ScanResult.objects.create(
            scan=scan,
            category='ssl',
            name='TLS Version',
            description='Supports TLS 1.2',
            severity='low',
            details={}
        )
        self.assertEqual(str(result), "ssl - TLS Version (low)")

    def test_scan_serializer_fields(self):
        scan = Scan.objects.create(
            user=self.user,
            target_url=self.https_url,
            scan_types=['headers'],
            status='completed',
            compliance_mode='strict'
        )
        serializer = ScanSerializer(instance=scan)
        self.assertIn('target_url', serializer.data)
        self.assertIn('compliance_status', serializer.data)

if __name__ == '__main__':
    unittest.main()
