# server/scanner/tests/test_models.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from scanner.models import Scan, ScanResult

User = get_user_model()

class ScanModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword',
            username='testuser'
        )
        
        self.scan = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            scan_types=['headers', 'ssl', 'content'],
            status='in_progress'
        )
    
    def test_scan_creation(self):
        """Test that Scan model creates a record correctly"""
        self.assertEqual(self.scan.target_url, 'https://example.com')
        self.assertEqual(self.scan.status, 'in_progress')
        self.assertEqual(self.scan.user, self.user)
        self.assertListEqual(self.scan.scan_types, ['headers', 'ssl', 'content'])
    
    def test_scan_str_representation(self):
        """Test the string representation of Scan"""
        expected_str = f"Scan {self.scan.id} - https://example.com"
        self.assertEqual(str(self.scan), expected_str)
    
    def test_scan_result_creation(self):
        """Test creating a ScanResult linked to a Scan"""
        result_data = {
            'headers': {'score': 80, 'issues': [{'severity': 'medium', 'description': 'Missing security header'}]},
            'ssl': {'score': 90, 'issues': []},
            'content': {'score': 70, 'issues': [{'severity': 'high', 'description': 'XSS vulnerability'}]}
        }
        
        scan_result = ScanResult.objects.create(
            scan=self.scan,
            results=result_data,
            overall_score=80
        )
        
        self.assertEqual(scan_result.scan, self.scan)
        self.assertEqual(scan_result.overall_score, 80)
        self.assertEqual(scan_result.results, result_data)