# server/tests/test_integration.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
from unittest.mock import patch
from scanner.models import Scan
from celery_app.tasks import run_security_scan

User = get_user_model()

class ScanIntegrationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword',
            username='testuser'
        )
        self.client.force_authenticate(user=self.user)
        
        self.scan_url = reverse('scan-list')
    
    
    @patch('scanner.services.header_scanner.HeaderScanner.scan')
    @patch('scanner.services.ssl_scanner.SSLScanner.scan')
    @patch('celery_app.tasks.run_security_scan.delay')
    def test_full_scan_flow(self, mock_task, mock_ssl_scan, mock_header_scan):
        """Test the full flow from creating a scan to getting results"""
        # Mock scanner responses
        mock_header_scan.return_value = {
            'score': 70,
            'issues': [
                {'severity': 'medium', 'description': 'Missing Content-Security-Policy header'}
            ]
        }
        
        mock_ssl_scan.return_value = {
            'score': 85,
            'issues': [],
            'certificate': {
                'issuer': 'Let\'s Encrypt',
                'valid_until': '2025-05-01',
                'subject': 'example.com'
            }
        }
        
        # Mock celery task to execute synchronously
        mock_task.side_effect = lambda scan_id: run_security_scan(scan_id)
        
        # 1. Create a new scan
        data = {
            'target_url': 'https://example.com',
            'scan_types': ['headers', 'ssl']
        }
        
        response = self.client.post(self.scan_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        scan_id = response.data['id']
        
        # 2. Check that scan was created and task was called
        self.assertTrue(Scan.objects.filter(id=scan_id).exists())
        mock_task.assert_called_once_with(scan_id)
        
        # 3. Get scan results
        scan_detail_url = reverse('scan-detail', args=[scan_id])
        response = self.client.get(scan_detail_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'completed')
        
        # 4. Verify scan results
        results = response.data['results']
        self.assertEqual(results['overall_score'], 77.5)  # Average of 70 and 85
        self.assertIn('headers', results)
        self.assertIn('ssl', results)
        
        # 5. Verify result details
        self.assertEqual(results['headers']['score'], 70)
        self.assertEqual(results['ssl']['score'], 85)
        self.assertEqual(len(results['headers']['issues']), 1)
        self.assertEqual(len(results['ssl']['issues']), 0)