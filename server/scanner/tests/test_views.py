# server/scanner/tests/test_views.py
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from scanner.models import Scan, ScanResult
import json

User = get_user_model()

class ScanAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword',
            username='testuser'
        )
        self.client.force_authenticate(user=self.user)
        
        self.scan_url = reverse('scan-list')
    
    def test_create_scan(self):
        """Test creating a new scan through the API"""
        data = {
            'target_url': 'https://example.com',
            'scan_types': ['headers', 'ssl']
        }
        
        response = self.client.post(self.scan_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 1)
        
        scan = Scan.objects.first()
        self.assertEqual(scan.target_url, 'https://example.com')
        self.assertEqual(scan.user, self.user)
        self.assertEqual(scan.status, 'queued')  # Assuming default status is 'queued'
        self.assertListEqual(scan.scan_types, ['headers', 'ssl'])
    
    def test_get_scan_list(self):
        """Test retrieving a list of user's scans"""
        # Create some test scans
        Scan.objects.create(
            user=self.user,
            target_url='https://example1.com',
            scan_types=['headers'],
            status='completed'
        )
        Scan.objects.create(
            user=self.user,
            target_url='https://example2.com',
            scan_types=['ssl', 'content'],
            status='in_progress'
        )
        
        response = self.client.get(self.scan_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)
        self.assertEqual(response.data[0]['target_url'], 'https://example1.com')
        self.assertEqual(response.data[1]['target_url'], 'https://example2.com')
    
    def test_get_scan_detail(self):
        """Test retrieving a specific scan"""
        scan = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            scan_types=['headers', 'ssl'],
            status='completed'
        )
        
        # Create a scan result
        result_data = {
            'headers': {'score': 80, 'issues': []},
            'ssl': {'score': 90, 'issues': []}
        }
        ScanResult.objects.create(
            scan=scan,
            results=result_data,
            overall_score=85
        )
        
        url = reverse('scan-detail', args=[scan.id])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['target_url'], 'https://example.com')
        self.assertEqual(response.data['status'], 'completed')
        self.assertEqual(response.data['results']['overall_score'], 85)
    
    def test_unauthorized_access(self):
        """Test that unauthenticated users cannot access scans"""
        # Logout
        self.client.force_authenticate(user=None)
        
        response = self.client.get(self.scan_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        response = self.client.post(self.scan_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)