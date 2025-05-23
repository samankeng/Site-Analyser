# server/ai_analyzer/tests/test_models.py
from django.test import TestCase
from unittest.mock import patch, MagicMock
import numpy as np
from ai_analyzer.ml.anomaly_detection.model import AnomalyDetectionModel
from ai_analyzer.ml.risk_scoring.model import RiskScoringModel
from ai_analyzer.ml.threat_detection.model import ThreatDetectionModel

class AnomalyDetectionModelTest(TestCase):
    def setUp(self):
        self.model = AnomalyDetectionModel()
        
    @patch('ai_analyzer.ml.anomaly_detection.model.joblib.load')
    def test_detect_anomalies(self, mock_load):
        # Mock the ML model
        mock_model = MagicMock()
        mock_model.predict.return_value = np.array([1, -1, 1])  # -1 indicates anomaly
        mock_load.return_value = mock_model
        
        # Test data
        data = [
            {'headers_score': 90, 'ssl_score': 95, 'content_score': 85},
            {'headers_score': 20, 'ssl_score': 30, 'content_score': 15},  # Anomaly
            {'headers_score': 80, 'ssl_score': 75, 'content_score': 85},
        ]
        
        results = self.model.detect_anomalies(data)
        
        # Verify results
        self.assertEqual(len(results), 3)
        self.assertFalse(results[0]['is_anomaly'])
        self.assertTrue(results[1]['is_anomaly'])
        self.assertFalse(results[2]['is_anomaly'])
        
        # The second item should have anomaly details
        self.assertIn('anomaly_score', results[1])
        self.assertIn('anomaly_factors', results[1])

class RiskScoringModelTest(TestCase):
    def setUp(self):
        self.model = RiskScoringModel()
    
    @patch('ai_analyzer.ml.risk_scoring.model.joblib.load')
    def test_calculate_risk_score(self, mock_load):
        # Mock the ML model
        mock_model = MagicMock()
        mock_model.predict.return_value = np.array([75, 40, 90])
        mock_load.return_value = mock_model
        
        # Test vulnerabilities
        vulnerabilities = [
            {
                'type': 'xss',
                'severity': 'medium',
                'description': 'Cross-site scripting vulnerability'
            },
            {
                'type': 'sql_injection',
                'severity': 'high',
                'description': 'SQL injection vulnerability'
            },
            {
                'type': 'csrf',
                'severity': 'low',
                'description': 'CSRF vulnerability'
            }
        ]
        
        results = self.model.calculate_risk_scores(vulnerabilities)
        
        # Verify results
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['risk_score'], 75)
        self.assertEqual(results[1]['risk_score'], 40)
        self.assertEqual(results[2]['risk_score'], 90)
        
        # Should maintain original vulnerability info
        self.assertEqual(results[0]['type'], 'xss')
        self.assertEqual(results[1]['severity'], 'high')
        self.assertEqual(results[2]['description'], 'CSRF vulnerability')

class ThreatDetectionModelTest(TestCase):
    def setUp(self):
        self.model = ThreatDetectionModel()
    
    @patch('ai_analyzer.ml.threat_detection.model.joblib.load')
    def test_detect_threats(self, mock_load):
        # Mock the ML model
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([
            [0.1, 0.9],  # High confidence threat
            [0.6, 0.4],  # Not a threat
            [0.3, 0.7],  # Medium confidence threat
        ])
        mock_load.return_value = mock_model
        
        # Test scan data
        scan_data = {
            'headers': {'Server': 'Apache/2.4.29', 'X-Powered-By': 'PHP/7.2.0'},
            'content': '<script>alert("XSS")</script>',
            'cookies': {'session': {'secure': False, 'httpOnly': False}}
        }
        
        results = self.model.detect_threats(scan_data)
        
        # Verify results
        self.assertEqual(len(results['threats']), 2)  # Should detect 2 threats
        
        # First threat should be high confidence
        self.assertGreaterEqual(results['threats'][0]['confidence'], 0.7)
        
        # Should provide threat descriptions
        self.assertIn('description', results['threats'][0])
        self.assertIn('severity', results['threats'][0])
        self.assertIn('remediation', results['threats'][0])