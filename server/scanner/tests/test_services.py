# server/scanner/tests/test_services.py
from django.test import TestCase
from unittest.mock import patch, MagicMock
from scanner.services.header_scanner import HeaderScanner
from scanner.services.ssl_scanner import SSLScanner
from scanner.services.content_scanner import ContentScanner

class HeaderScannerTest(TestCase):
    @patch('scanner.services.header_scanner.requests.get')
    def test_scan_headers(self, mock_get):
        # Mock response with missing security headers
        mock_response = MagicMock()
        mock_response.headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.29'
            # Missing security headers like Content-Security-Policy
        }
        mock_get.return_value = mock_response
        
        scanner = HeaderScanner()
        result = scanner.scan('https://example.com')
        
        # Verify scan results
        self.assertIn('score', result)
        self.assertIn('issues', result)
        
        # Should detect missing Content-Security-Policy
        csp_issue = next((issue for issue in result['issues'] 
                          if 'Content-Security-Policy' in issue['description']), None)
        self.assertIsNotNone(csp_issue)
        self.assertEqual(csp_issue['severity'], 'high')
        
        # Score should be lower due to missing security headers
        self.assertLess(result['score'], 80)

class SSLScannerTest(TestCase):
    @patch('scanner.services.ssl_scanner.socket.create_connection')
    @patch('scanner.services.ssl_scanner.ssl.create_default_context')
    def test_scan_ssl(self, mock_ssl_context, mock_create_connection):
        # Setup mocks for SSL testing
        mock_sock = MagicMock()
        mock_create_connection.return_value = mock_sock
        
        mock_ssl_sock = MagicMock()
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_context.return_value = mock_context
        
        # Mock SSL certificate info
        mock_ssl_sock.getpeercert.return_value = {
            'notAfter': 'Apr 30 23:59:59 2026 GMT',
            'subject': ((('commonName', 'example.com'),),),
            'version': 3,
            'serialNumber': '1234567890',
        }
        mock_ssl_sock.version.return_value = 'TLSv1.2'
        
        scanner = SSLScanner()
        result = scanner.scan('https://example.com')
        
        # Verify scan results
        self.assertIn('score', result)
        self.assertIn('issues', result)
        self.assertIn('certificate', result)
        
        # TLS 1.2 is good but not perfect (TLS 1.3 would be better)
        self.assertGreaterEqual(result['score'], 70)
        self.assertLess(result['score'], 100)

class ContentScannerTest(TestCase):
    @patch('scanner.services.content_scanner.requests.get')
    def test_scan_content(self, mock_get):
        # Mock HTML content with potential issues
        mock_response = MagicMock()
        mock_response.text = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <meta name="description" content="Test description">
            <!-- Missing viewport meta tag -->
            <script src="http://insecure.com/script.js"></script>
        </head>
        <body>
            <h1>Test Page</h1>
            <p>Some content</p>
            <img src="image.jpg" alt=""> <!-- Missing alt text -->
        </body>
        </html>
        """
        mock_get.return_value = mock_response
        
        scanner = ContentScanner()
        result = scanner.scan('https://example.com')
        
        # Verify scan results
        self.assertIn('score', result)
        self.assertIn('issues', result)
        
        # Should detect insecure script
        insecure_script = next((issue for issue in result['issues'] 
                               if 'insecure script' in issue['description'].lower()), None)
        self.assertIsNotNone(insecure_script)
        
        # Should detect accessibility issues (missing alt text)
        accessibility_issue = next((issue for issue in result['issues'] 
                                   if 'alt text' in issue['description'].lower()), None)
        self.assertIsNotNone(accessibility_issue)