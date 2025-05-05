# backend/ai_analyzer/ml/threat_detection/model.py

import logging
import numpy as np
import pickle
import os
from django.conf import settings
from pathlib import Path

logger = logging.getLogger(__name__)

class ThreatDetectionModel:
    """
    Threat detection model for identifying security threats in scan data
    This is a simple rule-based model with the ability to save/load more complex models
    """
    
    def __init__(self):
        self.model_path = os.path.join(
            getattr(settings, 'ML_MODELS_DIR', 'ml_models'),
            'threat_detection',
            'model.pkl'
        )
        self.model = None
        self.feature_names = []
        self.initialize_model()
    
    def initialize_model(self):
        """Initialize the threat detection model"""
        try:
            if os.path.exists(self.model_path):
                # Load pretrained model if it exists
                self.load_model()
                logger.info("Loaded threat detection model from disk")
            else:
                # Initialize with default rule-based model
                logger.info("No saved model found, using rule-based threat detection")
                self.model = None
                self.feature_names = [
                    'missing_security_headers',
                    'outdated_software',
                    'insecure_configuration',
                    'suspicious_behavior',
                    'input_validation'
                ]
        except Exception as e:
            logger.error(f"Error initializing threat detection model: {str(e)}")
            # Fall back to rule-based approach
            self.model = None
    
    def load_model(self):
        """Load a trained model from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data.get('model')
                self.feature_names = model_data.get('feature_names', [])
        except Exception as e:
            logger.error(f"Error loading threat detection model: {str(e)}")
            self.model = None
    
    def save_model(self):
        """Save the current model to disk"""
        if self.model is not None:
            try:
                # Ensure directory exists
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                
                # Save model and feature names
                with open(self.model_path, 'wb') as f:
                    pickle.dump({
                        'model': self.model,
                        'feature_names': self.feature_names
                    }, f)
                logger.info("Saved threat detection model to disk")
                return True
            except Exception as e:
                logger.error(f"Error saving threat detection model: {str(e)}")
                return False
        return False
    
    def detect_threats(self, scan_data):
        """
        Detect threats in scan data
        
        Args:
            scan_data (dict): Dictionary containing scan results data
            
        Returns:
            dict: Detected threats with scores and descriptions
        """
        # If we have a trained model, use it
        if self.model is not None:
            return self._detect_with_model(scan_data)
        
        # Otherwise use rule-based detection
        return self._detect_with_rules(scan_data)
    
    def _detect_with_model(self, scan_data):
        """Use trained model to detect threats"""
        try:
            # Extract features from scan data
            features = self._extract_features(scan_data)
            
            # Make prediction with model
            threat_score = self.model.predict_proba([features])[0, 1]  # Probability of threat
            
            # Interpret model predictions
            return self._interpret_prediction(threat_score, scan_data)
        except Exception as e:
            logger.error(f"Error during model-based threat detection: {str(e)}")
            # Fall back to rule-based detection
            return self._detect_with_rules(scan_data)
    
    def _extract_features(self, scan_data):
        """Extract features from scan data for model input"""
        # This is a placeholder for actual feature extraction
        # In a real implementation, you would extract relevant features based on self.feature_names
        
        features = np.zeros(len(self.feature_names))
        
        # Example feature extraction logic
        if 'headers' in scan_data:
            security_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'X-Frame-Options']
            missing_count = 0
            for header in security_headers:
                if header not in scan_data['headers']:
                    missing_count += 1
            
            # Set the missing_security_headers feature
            if 'missing_security_headers' in self.feature_names:
                idx = self.feature_names.index('missing_security_headers')
                features[idx] = missing_count / len(security_headers)  # Normalize
        
        # More feature extraction would happen here
        
        return features
    
    def _interpret_prediction(self, threat_score, scan_data):
        """Interpret model prediction and return structured threat data"""
        # Threshold for different threat levels
        if threat_score > 0.8:
            severity = 'critical'
        elif threat_score > 0.6:
            severity = 'high'
        elif threat_score > 0.4:
            severity = 'medium'
        elif threat_score > 0.2:
            severity = 'low'
        else:
            severity = 'info'
        
        # Prepare response
        return {
            'threat_detected': threat_score > 0.5,
            'threat_score': float(threat_score),
            'severity': severity,
            'model_based': True,
            'threats': self._generate_threat_descriptions(threat_score, scan_data)
        }
    
    def _generate_threat_descriptions(self, threat_score, scan_data):
        """Generate threat descriptions based on model prediction and scan data"""
        threats = []
        
        # Generate threats based on the predicted threat score and scan data
        # This is a placeholder that would be more sophisticated in a real implementation
        
        if threat_score > 0.5:
            # Missing security headers
            if 'headers' in scan_data:
                security_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'X-Frame-Options']
                for header in security_headers:
                    if header not in scan_data['headers']:
                        threats.append({
                            'type': 'missing_security_header',
                            'name': f"Missing {header}",
                            'description': f"The {header} header is missing, which increases vulnerability to attacks",
                            'severity': 'medium',
                            'confidence': min(0.9, threat_score + 0.2)
                        })
            
            # SSL vulnerabilities
            if 'ssl' in scan_data and threat_score > 0.7:
                threats.append({
                    'type': 'ssl_vulnerability',
                    'name': "Potential SSL vulnerability",
                    'description': "The model has detected patterns consistent with SSL/TLS vulnerabilities",
                    'severity': 'high',
                    'confidence': threat_score
                })
            
            # Content vulnerabilities
            if 'content' in scan_data and threat_score > 0.6:
                threats.append({
                    'type': 'content_vulnerability',
                    'name': "Potential content vulnerability",
                    'description': "Content analysis patterns suggest possible vulnerability",
                    'severity': 'medium',
                    'confidence': threat_score - 0.1
                })
        
        return threats
    
    def _detect_with_rules(self, scan_data):
        """Rule-based threat detection logic"""
        threats = []
        threat_score = 0.0
        
        # Check for missing security headers
        if 'headers' in scan_data:
            headers = scan_data['headers']
            self._check_security_headers(headers, threats)
        
        # Check for SSL/TLS vulnerabilities
        if 'ssl' in scan_data:
            ssl_data = scan_data['ssl']
            self._check_ssl_vulnerabilities(ssl_data, threats)
        
        # Check for content vulnerabilities
        if 'content' in scan_data:
            content_data = scan_data['content']
            self._check_content_vulnerabilities(content_data, threats)
        
        # Calculate overall threat score based on detected threats
        if threats:
            severity_weights = {
                'critical': 1.0,
                'high': 0.8,
                'medium': 0.5,
                'low': 0.3,
                'info': 0.1
            }
            
            total_weight = 0.0
            weighted_score = 0.0
            
            for threat in threats:
                weight = severity_weights.get(threat['severity'], 0.1)
                total_weight += weight
                weighted_score += weight
            
            if total_weight > 0:
                threat_score = weighted_score / total_weight
            else:
                threat_score = 0.0
        
        # Determine overall severity
        if threat_score > 0.8:
            severity = 'critical'
        elif threat_score > 0.6:
            severity = 'high'
        elif threat_score > 0.4:
            severity = 'medium'
        elif threat_score > 0.2:
            severity = 'low'
        else:
            severity = 'info'
        
        return {
            'threat_detected': threat_score > 0.5,
            'threat_score': float(threat_score),
            'severity': severity,
            'model_based': False,
            'threats': threats
        }
    
    def _check_security_headers(self, headers, threats):
        """Check for missing or misconfigured security headers"""
        security_headers = {
            'Content-Security-Policy': {
                'description': 'Content Security Policy helps prevent XSS attacks',
                'severity': 'high'
            },
            'X-XSS-Protection': {
                'description': 'X-XSS-Protection header prevents some XSS attacks',
                'severity': 'medium'
            },
            'X-Frame-Options': {
                'description': 'X-Frame-Options prevents clickjacking attacks',
                'severity': 'medium'
            },
            'Strict-Transport-Security': {
                'description': 'HSTS ensures secure connections are used',
                'severity': 'high'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing attacks',
                'severity': 'medium'
            }
        }
        
        # Check for missing headers
        for header, info in security_headers.items():
            if header not in headers:
                threats.append({
                    'type': 'missing_security_header',
                    'name': f"Missing {header}",
                    'description': f"The {header} header is missing. {info['description']}",
                    'severity': info['severity'],
                    'mitigation': f"Implement the {header} header in your web server configuration"
                })
    
    def _check_ssl_vulnerabilities(self, ssl_data, threats):
        """Check for SSL/TLS vulnerabilities"""
        # Check for outdated protocols
        if 'protocols' in ssl_data:
            protocols = ssl_data['protocols']
            if 'SSLv3' in protocols or 'TLSv1.0' in protocols or 'TLSv1.1' in protocols:
                threats.append({
                    'type': 'outdated_ssl_protocol',
                    'name': 'Outdated SSL/TLS Protocol',
                    'description': 'The server supports outdated SSL/TLS protocols that have known vulnerabilities',
                    'severity': 'high',
                    'mitigation': 'Disable SSLv3, TLSv1.0, and TLSv1.1. Only enable TLSv1.2 and TLSv1.3'
                })
        
        # Check for weak ciphers
        if 'ciphers' in ssl_data:
            weak_ciphers = [c for c in ssl_data['ciphers'] if 'NULL' in c or 'RC4' in c or 'DES' in c]
            if weak_ciphers:
                threats.append({
                    'type': 'weak_ssl_ciphers',
                    'name': 'Weak SSL/TLS Ciphers',
                    'description': f"The server supports weak cipher suites: {', '.join(weak_ciphers)}",
                    'severity': 'high',
                    'mitigation': 'Disable weak cipher suites and use only strong encryption'
                })
        
        # Check for certificate issues
        if 'certificate' in ssl_data:
            cert = ssl_data['certificate']
            
            # Check expiration
            if 'expired' in cert and cert['expired']:
                threats.append({
                    'type': 'expired_certificate',
                    'name': 'Expired SSL Certificate',
                    'description': 'The SSL certificate has expired',
                    'severity': 'critical',
                    'mitigation': 'Renew the SSL certificate with a trusted certificate authority'
                })
            
            # Check self-signed
            if 'self_signed' in cert and cert['self_signed']:
                threats.append({
                    'type': 'self_signed_certificate',
                    'name': 'Self-Signed Certificate',
                    'description': 'The server is using a self-signed certificate which browsers will flag as untrusted',
                    'severity': 'high',
                    'mitigation': 'Replace the self-signed certificate with one from a trusted certificate authority'
                })
    
    def _check_content_vulnerabilities(self, content_data, threats):
        """Check for content-related vulnerabilities"""
        # Check for sensitive information disclosure
        if 'sensitive_data' in content_data and content_data['sensitive_data']:
            for data_type, instances in content_data['sensitive_data'].items():
                if instances:
                    threats.append({
                        'type': 'sensitive_data_exposure',
                        'name': f"Exposed {data_type}",
                        'description': f"The site appears to be exposing sensitive {data_type} information",
                        'severity': 'high',
                        'mitigation': f"Review your application to prevent {data_type} exposure in page content"
                    })
        
        # Check for outdated libraries/frameworks
        if 'libraries' in content_data:
            for lib in content_data['libraries']:
                if lib.get('outdated'):
                    threats.append({
                        'type': 'outdated_library',
                        'name': f"Outdated {lib['name']}",
                        'description': f"Using version {lib.get('version')} of {lib['name']} which has known vulnerabilities",
                        'severity': 'medium',
                        'mitigation': f"Update {lib['name']} to the latest secure version"
                    })
        
        # Check for unsafe inline scripts
        if 'unsafe_inline' in content_data and content_data['unsafe_inline']:
            threats.append({
                'type': 'unsafe_inline_script',
                'name': 'Unsafe Inline Scripts',
                'description': 'The page contains inline scripts which can be vulnerable to XSS attacks',
                'severity': 'medium',
                'mitigation': 'Implement Content-Security-Policy and move scripts to external files'
            })