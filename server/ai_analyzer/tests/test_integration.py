# server/ai_analyzer/tests/test_integration.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from scanner.models import Scan, ScanResult
from server.ai_analyzer.services.ai_analysis_new import AIAnalysisService
from unittest.mock import patch

User = get_user_model()

class AIAnalysisIntegrationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword',
            username='testuser'
        )
        
        # Create a scan with results
        self.scan = Scan.objects.create(
            user=self.user,
            target_url='https://example.com',
            scan_types=['headers', 'ssl', 'content', 'cookies'],
            status='completed'
        )
        
        # Create scan results
        self.scan_result = ScanResult.objects.create(
            scan=self.scan,
            overall_score=75,
            results={
                'headers': {
                    'score': 70,
                    'issues': [
                        {'severity': 'medium', 'description': 'Missing security header'}
                    ]
                },
                'ssl': {
                    'score': 90,
                    'issues': []
                },
                'content': {
                    'score': 60,
                    'issues': [
                        {'severity': 'high', 'description': 'Potential XSS vulnerability'}
                    ]
                },
                'cookies': {
                    'score': 80,
                    'issues': [
                        {'severity': 'low', 'description': 'Missing SameSite attribute'}
                    ]
                }
            }
        )
        
        self.ai_service = AIAnalysisService()
    
    @patch('ai_analyzer.ml.anomaly_detection.model.AnomalyDetectionModel.detect_anomalies')
    @patch('ai_analyzer.ml.risk_scoring.model.RiskScoringModel.calculate_risk_scores')
    @patch('ai_analyzer.ml.threat_detection.model.ThreatDetectionModel.detect_threats')
    def test_ai_analysis_enhances_scan_results(self, mock_detect_threats, 
                                              mock_risk_scoring, mock_detect_anomalies):
        """Test that AI analysis enhances scan results"""
        # Mock AI model responses
        mock_detect_anomalies.return_value = [
            {'is_anomaly': False, 'anomaly_score': 0.1},
            {'is_anomaly': True, 'anomaly_score': 0.8, 
             'anomaly_factors': ['unusually low content score']}
        ]
        
        mock_risk_scoring.return_value = [
            {'risk_score': 65, 'priority': 'medium', 'original_severity': 'medium'},
            {'risk_score': 90, 'priority': 'high', 'original_severity': 'high'},
            {'risk_score': 35, 'priority': 'low', 'original_severity': 'low'}
        ]
        
        mock_detect_threats.return_value = {
            'threats': [
                {
                    'type': 'xss',
                    'confidence': 0.89,
                    'severity': 'high',
                    'description': 'Cross-site scripting vulnerability detected',
                    'remediation': 'Implement Content-Security-Policy header'
                }
            ],
            'overall_threat_level': 'high'
        }
        
        # Run AI analysis
        enhanced_results = self.ai_service.analyze_scan_results(self.scan_result)
        
        # Verify AI enhancements
        self.assertIn('ai_analysis', enhanced_results)
        ai_analysis = enhanced_results['ai_analysis']
        
        # Check anomaly detection
        self.assertIn('anomalies', ai_analysis)
        self.assertEqual(len(ai_analysis['anomalies']), 1)  # One anomaly detected
        self.assertIn('unusually low content score', ai_analysis['anomalies'][0]['factors'])
        
        # Check risk scoring
        self.assertIn('prioritized_issues', ai_analysis)
        self.assertEqual(len(ai_analysis['prioritized_issues']), 3)
        
        # The high priority item should be first
        self.assertEqual(ai_analysis['prioritized_issues'][0]['priority'], 'high')
        self.assertEqual(ai_analysis['prioritized_issues'][0]['risk_score'], 90)
        
        # Check threat detection
        self.assertIn('detected_threats', ai_analysis)
        self.assertEqual(len(ai_analysis['detected_threats']), 1)
        self.assertEqual(ai_analysis['detected_threats'][0]['type'], 'xss')
        self.assertIn('remediation', ai_analysis['detected_threats'][0])
        
        # Check recommendations
        self.assertIn('recommendations', ai_analysis)
        self.assertGreater(len(ai_analysis['recommendations']), 0)