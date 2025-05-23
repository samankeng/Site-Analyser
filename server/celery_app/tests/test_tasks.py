# server/celery_app/tests/test_tasks.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
from celery_app.tasks import run_security_scan
from scanner.models import Scan, ScanResult

User = get_user_model()

class CeleryTasksTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword',
            username='testuser'
        )
        
        self.scan = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            scan_types=['headers', 'ssl'],
            status='queued'
        )
    
    @patch('scanner.services.scan_service.ScanService.run_scan')
    def test_run_security_scan_task(self, mock_run_scan):
        """Test that run_security_scan task works correctly"""
        # Mock scan service result
        mock_result = {
            'headers': {
                'score': 70,
                'issues': [{'severity': 'medium', 'description': 'Missing header'}]
            },
            'ssl': {
                'score': 90,
                'issues': []
            },
            'overall_score': 80
        }
        mock_run_scan.return_value = mock_result
        
        # Run task
        run_security_scan(self.scan.id)
        
        # Refresh scan from database
        self.scan.refresh_from_db()
        
        # Verify scan status changed
        self.assertEqual(self.scan.status, 'completed')
        
        # Verify scan result was created
        self.assertTrue(ScanResult.objects.filter(scan=self.scan).exists())
        
        scan_result = ScanResult.objects.get(scan=self.scan)
        self.assertEqual(scan_result.overall_score, 80)
        self.assertEqual(scan_result.results, mock_result)
    
    @patch('scanner.services.scan_service.ScanService.run_scan')
    def test_run_security_scan_handles_errors(self, mock_run_scan):
        """Test that run_security_scan task handles errors correctly"""
        # Mock an error in scan service
        mock_run_scan.side_effect = Exception('Scan error')
        
        # Run task
        run_security_scan(self.scan.id)
        
        # Refresh scan from database
        self.scan.refresh_from_db()
        
        # Verify scan status changed to failed
        self.assertEqual(self.scan.status, 'failed')
        
        # Verify error message was saved
        self.assertIn('error_message', self.scan.metadata)
        self.assertEqual(self.scan.metadata['error_message'], 'Scan error')