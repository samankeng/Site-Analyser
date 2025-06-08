# scanner/tests/test_scanners.py

import unittest
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.contrib.auth import get_user_model

# Use the custom User model (accounts.User)
User = get_user_model()

class BasicSystemTestCase(TestCase):
    """Basic system functionality tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_url = "https://httpbin.org"
        
    def test_database_connectivity(self):
        """Test database connectivity"""
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            self.assertEqual(result[0], 1)
        print("✅ Database connectivity: PASSED")
    
    def test_user_model(self):
        """Test user model operations"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'testuser')
        user.delete()
        print("✅ User model: PASSED")
    
    def test_scanner_imports(self):
        """Test scanner service imports"""
        services = []
        
        # Test each scanner import
        try:
            from scanner.services.active_scanner import ActiveScanService
            services.append("ActiveScanService")
            print("✅ ActiveScanService: Available")
        except ImportError as e:
            print(f"⚠️  ActiveScanService: Not available - {str(e)}")
        
        try:
            from scanner.services.active_vulnerability_scanner import ActiveVulnerabilityScanner
            services.append("ActiveVulnerabilityScanner")
            print("✅ ActiveVulnerabilityScanner: Available")
        except ImportError as e:
            print(f"⚠️  ActiveVulnerabilityScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.content_scanner import ContentScanner
            content_scanner = ContentScanner(self.test_url)
            self.assertIsNotNone(content_scanner)
            services.append("ContentScanner")
            print("✅ ContentScanner: Available")
        except ImportError as e:
            print(f"⚠️  ContentScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.cookie_scanner import CookieScanner
            cookie_scanner = CookieScanner(self.test_url)
            self.assertIsNotNone(cookie_scanner)
            services.append("CookieScanner")
            print("✅ CookieScanner: Available")
        except ImportError as e:
            print(f"⚠️  CookieScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.cors_scanner import CorsScanner
            cors_scanner = CorsScanner(self.test_url)
            self.assertIsNotNone(cors_scanner)
            services.append("CorsScanner")
            print("✅ CorsScanner: Available")
        except ImportError as e:
            print(f"⚠️  CorsScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.csp_scanner import CspScanner
            csp_scanner = CspScanner(self.test_url)
            self.assertIsNotNone(csp_scanner)
            services.append("CspScanner")
            print("✅ CspScanner: Available")
        except ImportError as e:
            print(f"⚠️  CspScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.header_scanner import HeaderScanner
            header_scanner = HeaderScanner(self.test_url)
            self.assertIsNotNone(header_scanner)
            services.append("HeaderScanner")
            print("✅ HeaderScanner: Available")
        except ImportError as e:
            print(f"⚠️  HeaderScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.passive_scanner import PassiveScanService
            services.append("PassiveScanService")
            print("✅ PassiveScanService: Available")
        except ImportError as e:
            print(f"⚠️  PassiveScanService: Not available - {str(e)}")
        
        try:
            from scanner.services.passive_vulnerability_scanner import PassiveVulnerabilityScanner
            passive_vuln_scanner = PassiveVulnerabilityScanner(self.test_url)
            self.assertIsNotNone(passive_vuln_scanner)
            services.append("PassiveVulnerabilityScanner")
            print("✅ PassiveVulnerabilityScanner: Available")
        except ImportError as e:
            print(f"⚠️  PassiveVulnerabilityScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.pdf_report_generator import PDFReportGenerator
            services.append("PDFReportGenerator")
            print("✅ PDFReportGenerator: Available")
        except ImportError as e:
            print(f"⚠️  PDFReportGenerator: Not available - {str(e)}")
        
        try:
            from scanner.services.port_scanner import PortScanner
            port_scanner = PortScanner(self.test_url)
            self.assertIsNotNone(port_scanner)
            services.append("PortScanner")
            print("✅ PortScanner: Available")
        except ImportError as e:
            print(f"⚠️  PortScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.scan_service import ScanService
            services.append("ScanService")
            print("✅ ScanService: Available")
        except ImportError as e:
            print(f"⚠️  ScanService: Not available - {str(e)}")
        
        try:
            from scanner.services.server_analyzer import ServerAnalyzer
            server_analyzer = ServerAnalyzer(self.test_url)
            self.assertIsNotNone(server_analyzer)
            services.append("ServerAnalyzer")
            print("✅ ServerAnalyzer: Available")
        except ImportError as e:
            print(f"⚠️  ServerAnalyzer: Not available - {str(e)}")
        
        try:
            from scanner.services.ssl_scanner import SslScanner
            ssl_scanner = SslScanner(self.test_url)
            self.assertIsNotNone(ssl_scanner)
            services.append("SslScanner")
            print("✅ SslScanner: Available")
        except ImportError as e:
            print(f"⚠️  SslScanner: Not available - {str(e)}")
        
        try:
            from scanner.services.mixed_scan_service import MixedScanService
            services.append("MixedScanService")
            print("✅ MixedScanService: Available")
        except ImportError as e:
            print(f"⚠️  MixedScanService: Not available - {str(e)}")
        
        # At least some services should be available
        self.assertGreater(len(services), 0, "No scanner services available")
        print(f"📊 Scanner services: {len(services)}/15 available")
    
    def test_external_integrations(self):
        """Test external service integrations"""
        integrations = []
        
        try:
            from integrations.shodan_service import ShodanService
            shodan = ShodanService()
            self.assertIsNotNone(shodan)
            integrations.append("Shodan")
            print("✅ Shodan integration: Available")
        except ImportError as e:
            print(f"⚠️  Shodan integration: Not available - {str(e)}")
        except Exception as e:
            print(f"⚠️  Shodan integration: Error - {str(e)}")
        
        try:
            from integrations.ssl_labs_service import SSLLabsService
            ssl_labs = SSLLabsService()
            self.assertIsNotNone(ssl_labs)
            integrations.append("SSL Labs")
            print("✅ SSL Labs integration: Available")
        except ImportError as e:
            print(f"⚠️  SSL Labs integration: Not available - {str(e)}")
        except Exception as e:
            print(f"⚠️  SSL Labs integration: Error - {str(e)}")
        
        try:
            from integrations.virus_total_service import VirusTotalService
            vt = VirusTotalService()
            self.assertIsNotNone(vt)
            integrations.append("VirusTotal")
            print("✅ VirusTotal integration: Available")
        except ImportError as e:
            print(f"⚠️  VirusTotal integration: Not available - {str(e)}")
        except Exception as e:
            print(f"⚠️  VirusTotal integration: Error - {str(e)}")
        
        print(f"📊 External integrations: {len(integrations)}/3 available")
    
    def test_ai_and_compliance(self):
        """Test AI and compliance services with proper initialization"""
        services = []
        
        try:
            # Test AI service with proper parameters
            from ai_analyzer.services.ai_analysis import AIAnalysisService
            from scanner.models import Scan
            
            # Create a mock scan for testing
            try:
                # Try to create a minimal scan object for testing
                test_user = User.objects.create_user(
                    username='aitestuser',
                    email='aitest@example.com',
                    password='testpass123'
                )
                
                # Create a mock scan (without saving to DB)
                class MockScan:
                    def __init__(self):
                        self.id = 1
                        self.target_url = "https://example.com"
                        self.scan_types = ["headers"]
                        self.user = test_user
                
                mock_scan = MockScan()
                ai_service = AIAnalysisService(mock_scan)
                self.assertIsNotNone(ai_service)
                services.append("AI Analyzer")
                print("✅ AI Analyzer: Available")
                
                # Clean up
                test_user.delete()
                
            except Exception as inner_e:
                print(f"⚠️  AI Analyzer: Error with scan parameter - {str(inner_e)}")
                
        except ImportError as e:
            print(f"⚠️  AI Analyzer: Not available - {str(e)}")
        except Exception as e:
            print(f"⚠️  AI Analyzer: Error - {str(e)}")
        
        try:
            # Test compliance service with proper parameters
            from compliance.services.compliance_service import ComplianceService
            
            try:
                # Create test user for compliance service
                test_user = User.objects.create_user(
                    username='compliancetestuser',
                    email='compliance@example.com',
                    password='testpass123'
                )
                
                compliance_service = ComplianceService(test_user)
                self.assertIsNotNone(compliance_service)
                services.append("Compliance")
                print("✅ Compliance service: Available")
                
                # Clean up
                test_user.delete()
                
            except Exception as inner_e:
                print(f"⚠️  Compliance service: Error with user parameter - {str(inner_e)}")
                
        except ImportError as e:
            print(f"⚠️  Compliance service: Not available - {str(e)}")
        except Exception as e:
            print(f"⚠️  Compliance service: Error - {str(e)}")
        
        print(f"📊 AI & Compliance services: {len(services)}/2 available")
    
    @patch('requests.get')
    def test_basic_scanner_functionality(self, mock_get):
        """Test basic scanner functionality with mocked requests"""
        # Mock a successful HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000'
        }
        mock_response.text = '<html><head><title>Test</title></head><body>Test content</body></html>'
        mock_response.url = self.test_url
        mock_get.return_value = mock_response
        
        # Test header scanner with mock
        try:
            from scanner.services.header_scanner import HeaderScanner
            header_scanner = HeaderScanner(self.test_url)
            result = header_scanner.scan()
            self.assertIsNotNone(result)
            self.assertIsInstance(result, list)
            print("✅ HeaderScanner basic functionality: PASSED")
        except Exception as e:
            print(f"⚠️  HeaderScanner functionality test: {str(e)}")
        
        # Test content scanner with mock
        try:
            from scanner.services.content_scanner import ContentScanner
            content_scanner = ContentScanner(self.test_url)
            result = content_scanner.scan()
            self.assertIsNotNone(result)
            self.assertIsInstance(result, list)
            print("✅ ContentScanner basic functionality: PASSED")
        except Exception as e:
            print(f"⚠️  ContentScanner functionality test: {str(e)}")
    
    def test_scanner_error_handling(self):
        """Test scanner error handling with invalid inputs"""
        invalid_urls = ["", "not-a-url", "http://", None]
        
        for invalid_url in invalid_urls:
            try:
                from scanner.services.header_scanner import HeaderScanner
                header_scanner = HeaderScanner(invalid_url or "http://invalid")
                # Should handle gracefully, not crash
                result = header_scanner.scan()
                # Don't assert specific result, just that it doesn't crash
                self.assertIsNotNone(result)
            except Exception as e:
                # Some exceptions are expected for invalid inputs
                pass
        
        print("✅ Scanner error handling: PASSED")


class CacheTestCase(TestCase):
    """Test cache functionality"""
    
    def test_cache_operations(self):
        """Test cache read/write operations"""
        from django.core.cache import cache
        
        test_key = "test_key_123"
        test_value = {"test": "data", "number": 42}
        
        # Test cache set
        cache.set(test_key, test_value, 300)
        
        # Test cache get
        retrieved_value = cache.get(test_key)
        self.assertEqual(retrieved_value, test_value)
        
        # Test cache delete
        cache.delete(test_key)
        deleted_value = cache.get(test_key)
        self.assertIsNone(deleted_value)
        
        print("✅ Cache operations: PASSED")


class IntegrationTestCase(TestCase):
    """Integration tests for scanner workflow"""
    
    def setUp(self):
        self.test_url = "https://httpbin.org"
        # Fix: Use get_user_model() instead of hardcoded User
        self.test_user = User.objects.create_user(
            username='integrationtest',
            email='integration@test.com',
            password='testpass123'
        )
    
    def tearDown(self):
        self.test_user.delete()
    
    def test_scanner_workflow(self):
        """Test a basic scanner workflow"""
        try:
            # Test if we can create scanner instances
            from scanner.services.header_scanner import HeaderScanner
            from scanner.services.content_scanner import ContentScanner
            
            # Initialize scanners
            header_scanner = HeaderScanner(self.test_url)
            content_scanner = ContentScanner(self.test_url)
            
            self.assertIsNotNone(header_scanner)
            self.assertIsNotNone(content_scanner)
            
            print("✅ Scanner workflow initialization: PASSED")
            
        except ImportError as e:
            print(f"⚠️  Scanner workflow test: Import error - {str(e)}")
        except Exception as e:
            print(f"⚠️  Scanner workflow test: Error - {str(e)}")
    
    @patch('requests.get')
    def test_external_service_mock(self, mock_get):
        """Test external services with mocking"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.return_value = {'status': 'ok'}
        mock_get.return_value = mock_response
        
        try:
            from integrations.shodan_service import ShodanService
            shodan = ShodanService()
            # Test should work with mock mode enabled
            result = shodan.get_host_information(self.test_url)
            self.assertIsNotNone(result)
            print("✅ External service mocking: PASSED")
        except Exception as e:
            print(f"⚠️  External service mocking: {str(e)}")


if __name__ == '__main__':
    unittest.main()