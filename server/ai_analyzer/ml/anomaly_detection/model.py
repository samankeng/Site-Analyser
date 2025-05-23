# backend/ai_analyzer/ml/anomaly_detection/model.py

import logging
import numpy as np
import pickle
import os
from django.conf import settings
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class AnomalyDetectionModel:
    """
    Anomaly detection model for identifying unusual patterns in security scan data
    Uses statistical approaches and can be extended with more complex machine learning models
    """
    
    def __init__(self):
        self.model_path = os.path.join(
            getattr(settings, 'ML_MODELS_DIR', 'ml_models'),
            'anomaly_detection',
            'model.pkl'
        )
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.threshold = 0.8  # Default anomaly threshold score
        self.initialize_model()
    
    def train_model(self, training_data):
        """Train the anomaly detection model"""
        try:
            features = np.array(training_data['features'])
            labels = np.array(training_data['labels'])
            
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train Isolation Forest model
            self.model = IsolationForest(
                contamination=0.1,  # Expected proportion of anomalies
                random_state=42
            )
            self.model.fit(scaled_features)
            
            # Save model and scaler
            self.save_model()
            return True
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            return False
        
    def initialize_model(self):
        """Initialize the anomaly detection model"""
        try:
            if os.path.exists(self.model_path):
                # Load pretrained model if it exists
                self.load_model()
                logger.info("Loaded anomaly detection model from disk")
            else:
                # Initialize with default statistical model
                logger.info("No saved model found, using statistical anomaly detection")
                self.model = None
                self.feature_names = [
                    'response_time',
                    'header_count',
                    'ssl_score',
                    'content_size',
                    'external_requests'
                ]
        except Exception as e:
            logger.error(f"Error initializing anomaly detection model: {str(e)}")
            # Fall back to statistical approach
            self.model = None
    
    def load_model(self):
        """Load the model, scaler, and metadata"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data.get('model')
                self.scaler = model_data.get('scaler')
                self.feature_names = model_data.get('feature_names', [])
                self.threshold = model_data.get('threshold', 0.8)
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None
    
    def save_model(self):
        """Save the model, scaler, and metadata"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'threshold': self.threshold
            }
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info("Saved anomaly detection model to disk")
            return True
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            return False
        
    
    def detect_anomalies(self, scan_data):
        """
        Detect anomalies in scan data
        
        Args:
            scan_data (dict): Dictionary containing scan results data
            
        Returns:
            dict: Detected anomalies with scores and descriptions
        """
        # If we have a trained model, use it
        if self.model is not None:
            return self._detect_with_model(scan_data)
        
        # Otherwise use rule-based/statistical detection
        return self._detect_with_statistics(scan_data)
    
    def _detect_with_model(self, scan_data):
        """Use trained model to detect anomalies"""
        try:
            # Extract features from scan data
            features = self._extract_features(scan_data)
            
            # Make prediction with model (anomaly score)
            # This assumes a model that returns anomaly scores (higher = more anomalous)
            anomaly_score = self.model.predict([features])[0]
            
            # Detect if it's an anomaly based on threshold
            is_anomaly = anomaly_score > self.threshold
            
            # Generate anomaly details
            anomalies = []
            if is_anomaly:
                # Use feature importance or other model properties to explain anomalies
                anomalies = self._generate_anomaly_descriptions(anomaly_score, features, scan_data)
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': float(anomaly_score),
                'model_based': True,
                'anomalies': anomalies
            }
            
        except Exception as e:
            logger.error(f"Error during model-based anomaly detection: {str(e)}")
            # Fall back to statistical approach
            return self._detect_with_statistics(scan_data)
    
    def _extract_features(self, scan_data):
        """Extract features from scan data for model input"""
        # This is a placeholder for actual feature extraction
        # In a real implementation, you would extract relevant features based on self.feature_names
        
        features = np.zeros(len(self.feature_names))
        
        # Extract common features
        if 'response_time' in self.feature_names and 'performance' in scan_data:
            idx = self.feature_names.index('response_time')
            features[idx] = scan_data['performance'].get('response_time', 0)
        
        if 'header_count' in self.feature_names and 'headers' in scan_data:
            idx = self.feature_names.index('header_count')
            features[idx] = len(scan_data['headers'])
        
        if 'ssl_score' in self.feature_names and 'ssl' in scan_data:
            idx = self.feature_names.index('ssl_score')
            ssl_data = scan_data['ssl']
            # Example: calculate SSL score based on protocol version, cipher strength, etc.
            features[idx] = self._calculate_ssl_score(ssl_data)
        
        if 'content_size' in self.feature_names and 'content' in scan_data:
            idx = self.feature_names.index('content_size')
            content_data = scan_data['content']
            features[idx] = content_data.get('size', 0)
        
        if 'external_requests' in self.feature_names and 'content' in scan_data:
            idx = self.feature_names.index('external_requests')
            content_data = scan_data['content']
            features[idx] = len(content_data.get('external_resources', []))
        
        # More feature extraction would happen here
        
        return features
    
    def _calculate_ssl_score(self, ssl_data):
        """Calculate a score for SSL configuration (higher is better)"""
        score = 100  # Start with perfect score
        
        # Reduce score for older protocols
        if 'protocols' in ssl_data:
            protocols = ssl_data['protocols']
            if 'SSLv3' in protocols:
                score -= 50
            if 'TLSv1.0' in protocols:
                score -= 30
            if 'TLSv1.1' in protocols:
                score -= 20
            if 'TLSv1.2' not in protocols and 'TLSv1.3' not in protocols:
                score -= 40
        
        # Reduce score for weak ciphers
        if 'ciphers' in ssl_data:
            ciphers = ssl_data['ciphers']
            weak_ciphers = [c for c in ciphers if 'NULL' in c or 'RC4' in c or 'DES' in c]
            score -= (len(weak_ciphers) * 15)
        
        # Certificate issues
        if 'certificate' in ssl_data:
            cert = ssl_data['certificate']
            if cert.get('expired', False):
                score -= 80
            if cert.get('self_signed', False):
                score -= 50
            if 'days_until_expiry' in cert and cert['days_until_expiry'] < 30:
                score -= 30
        
        # Ensure score is between 0 and 100
        return max(0, min(100, score)) / 100.0  # Normalize to 0-1
    
    def _generate_anomaly_descriptions(self, anomaly_score, features, scan_data):
        """Generate descriptions of detected anomalies"""
        anomalies = []
        
        # This would use model internals to explain the anomalies
        # For now, we'll use a simplified approach that looks at the most anomalous features
        
        # For demonstration, check which features are most different from expected values
        # In a real implementation, this would be informed by the model's decision
        
        if 'response_time' in self.feature_names and 'performance' in scan_data:
            idx = self.feature_names.index('response_time')
            response_time = scan_data['performance'].get('response_time', 0)
            if response_time > 2.0:  # Arbitrary threshold for example
                anomalies.append({
                    'component': 'Response Time',
                    'description': f'Unusually slow response time: {response_time:.2f} seconds',
                    'severity': 'medium',
                    'score': min(1.0, response_time / 5.0)  # Scale severity with response time
                })
        
        if 'ssl_score' in self.feature_names and 'ssl' in scan_data:
            idx = self.feature_names.index('ssl_score')
            ssl_score = features[idx]
            if ssl_score < 0.7:  # If SSL score is poor
                anomalies.append({
                    'component': 'SSL/TLS Configuration',
                    'description': 'Unusual or insecure SSL/TLS configuration detected',
                    'severity': 'high' if ssl_score < 0.5 else 'medium',
                    'score': 1.0 - ssl_score
                })
        
        # More anomaly detections would be added here
        
        return anomalies
    
    def _detect_with_statistics(self, scan_data):
        """Use statistical methods to detect anomalies"""
        anomalies = []
        anomaly_score = 0.0
        
        # Check performance anomalies
        if 'performance' in scan_data:
            performance = scan_data['performance']
            self._check_performance_anomalies(performance, anomalies)
        
        # Check header anomalies
        if 'headers' in scan_data:
            headers = scan_data['headers']
            self._check_header_anomalies(headers, anomalies)
        
        # Check SSL anomalies
        if 'ssl' in scan_data:
            ssl_data = scan_data['ssl']
            self._check_ssl_anomalies(ssl_data, anomalies)
        
        # Check content anomalies
        if 'content' in scan_data:
            content = scan_data['content']
            self._check_content_anomalies(content, anomalies)
        
        # Calculate overall anomaly score based on detected anomalies
        if anomalies:
            total_score = sum(a.get('score', 0.5) for a in anomalies)
            anomaly_score = min(1.0, total_score / len(anomalies))
        
        return {
            'is_anomaly': anomaly_score > self.threshold,
            'anomaly_score': float(anomaly_score),
            'model_based': False,
            'anomalies': anomalies
        }
    
    def _check_performance_anomalies(self, performance_data, anomalies):
        """Check for performance-related anomalies"""
        # Check for slow response time
        if 'response_time' in performance_data:
            response_time = performance_data['response_time']
            if response_time > 2.0:  # Arbitrary threshold
                anomalies.append({
                    'component': 'Response Time',
                    'description': f'Unusually slow response time: {response_time:.2f} seconds',
                    'severity': 'medium',
                    'recommendation': 'Optimize server response time through caching, code optimization, or server upgrades',
                    'score': min(1.0, response_time / 5.0)
                })
        
        # Check for large page size
        if 'page_size' in performance_data:
            page_size = performance_data['page_size']
            if page_size > 3000000:  # 3MB
                anomalies.append({
                    'component': 'Page Size',
                    'description': f'Unusually large page size: {page_size / 1000000:.2f} MB',
                    'severity': 'low',
                    'recommendation': 'Optimize images, minify CSS/JS, and remove unnecessary resources',
                    'score': min(1.0, page_size / 10000000)
                })
    
    def _check_header_anomalies(self, headers, anomalies):
        """Check for anomalies in HTTP headers"""
        # Check for unusual server headers that might reveal information
        sensitive_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-Runtime']
        for header in sensitive_headers:
            if header in headers:
                anomalies.append({
                    'component': 'Information Disclosure',
                    'description': f'Header {header} reveals potentially sensitive information: {headers[header]}',
                    'severity': 'medium',
                    'recommendation': f'Remove or sanitize the {header} header',
                    'score': 0.7
                })
        
        # Check for unusually large number of headers
        if len(headers) > 20:  # Arbitrary threshold
            anomalies.append({
                'component': 'Header Count',
                'description': f'Unusually high number of HTTP headers: {len(headers)}',
                'severity': 'low',
                'recommendation': 'Review headers and remove unnecessary ones',
                'score': 0.3
            })
    
    def _check_ssl_anomalies(self, ssl_data, anomalies):
        """Check for anomalies in SSL configuration"""
        # Check for certificate expiring soon
        if 'certificate' in ssl_data:
            cert = ssl_data['certificate']
            if 'days_until_expiry' in cert:
                days = cert['days_until_expiry']
                if days < 30:
                    severity = 'high' if days < 7 else 'medium'
                    anomalies.append({
                        'component': 'SSL Certificate',
                        'description': f'Certificate will expire in {days} days',
                        'severity': severity,
                        'recommendation': 'Renew SSL certificate before it expires',
                        'score': 1.0 if days < 7 else 0.7
                    })
        
        # Check for unusual cipher preference
        if 'preferred_cipher' in ssl_data:
            cipher = ssl_data['preferred_cipher']
            if 'DHE' not in cipher and 'ECDHE' not in cipher:
                anomalies.append({
                    'component': 'SSL Cipher',
                    'description': f'Unusual preferred cipher: {cipher} (Perfect Forward Secrecy not prioritized)',
                    'severity': 'medium',
                    'recommendation': 'Configure server to prioritize ECDHE or DHE cipher suites',
                    'score': 0.6
                })
    
    def _check_content_anomalies(self, content_data, anomalies):
        """Check for content-related anomalies"""
        # Check for unusually high number of external resources
        if 'external_resources' in content_data:
            external_count = len(content_data['external_resources'])
            if external_count > 30:  # Arbitrary threshold
                anomalies.append({
                    'component': 'External Resources',
                    'description': f'Unusually high number of external resources: {external_count}',
                    'severity': 'medium',
                    'recommendation': 'Reduce dependencies on external resources to improve security and performance',
                    'score': min(1.0, external_count / 50)
                })
        
        # Check for uncommon JavaScript libraries
        if 'libraries' in content_data:
            libraries = content_data['libraries']
            common_libs = ['jquery', 'bootstrap', 'react', 'angular', 'vue']
            
            uncommon_libs = []
            for lib in libraries:
                lib_name = lib.get('name', '').lower()
                if not any(common in lib_name for common in common_libs):
                    uncommon_libs.append(lib.get('name'))
            
            if len(uncommon_libs) > 3:  # If more than 3 uncommon libraries
                anomalies.append({
                    'component': 'JavaScript Libraries',
                    'description': f'Unusual JavaScript libraries detected: {", ".join(uncommon_libs[:5])}' +
                                  (f' and {len(uncommon_libs) - 5} more' if len(uncommon_libs) > 5 else ''),
                    'severity': 'low',
                    'recommendation': 'Review and validate uncommon JavaScript libraries for security risks',
                    'score': 0.5
                })
        
        # Check for excessive inline script volume
        if 'inline_scripts' in content_data:
            inline_count = len(content_data['inline_scripts'])
            inline_size = sum(len(s) for s in content_data['inline_scripts'])
            
            if inline_count > 15 or inline_size > 50000:  # Many scripts or large total size
                anomalies.append({
                    'component': 'Inline Scripts',
                    'description': f'Unusual amount of inline JavaScript: {inline_count} scripts, {inline_size/1000:.1f} KB',
                    'severity': 'medium',
                    'recommendation': 'Move inline scripts to external files and implement Content-Security-Policy',
                    'score': 0.6
                })