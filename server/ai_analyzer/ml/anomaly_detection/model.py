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

        # Add these new attributes
        self.historical_data_cache = {}
        self.smart_thresholds = {}
        
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
        
    def detect_scan_failure_anomalies(self, scan_results):
        """Detect anomalies from scan failures and errors"""
        anomalies = []
        
        # Convert QuerySet to list if needed
        if hasattr(scan_results, 'all'):
            results_list = list(scan_results.all())
        else:
            results_list = scan_results
        
        # Check for SSL certificate expiration
        ssl_errors = [r for r in results_list if 
                    'certificate has expired' in r.description or
                    'CERTIFICATE_VERIFY_FAILED' in r.description]
        
        if ssl_errors:
            anomalies.append({
                'component': 'SSL Certificate',
                'description': 'SSL certificate has expired, preventing secure connections',
                'severity': 'high',
                'recommendation': 'Renew SSL certificate immediately to restore HTTPS functionality',
                'score': 1.0
            })
        
        # Check for connection failures
        connection_errors = [r for r in results_list if 
                            'Failed to connect' in r.description or
                            'Max retries exceeded' in r.description]
        
        if len(connection_errors) > 3:
            anomalies.append({
                'component': 'Website Availability',
                'description': f'Multiple connection failures detected ({len(connection_errors)} failed attempts)',
                'severity': 'high',
                'recommendation': 'Check server status, DNS configuration, and network connectivity',
                'score': 0.9
            })
        
        # Check for scan timeouts
        timeout_errors = [r for r in results_list if 
                        'SoftTimeLimitExceeded' in r.description or
                        'timeout' in r.description.lower()]
        
        if timeout_errors:
            anomalies.append({
                'component': 'Performance',
                'description': 'Scan operations timed out indicating slow server responses',
                'severity': 'medium',
                'recommendation': 'Optimize server performance and check for resource bottlenecks',
                'score': 0.7
            })
        
        # Check for CORS configuration issues
        cors_errors = [r for r in results_list if 
                    r.category == 'cors' and 'Failed to analyze CORS' in r.description]
        
        if len(cors_errors) > 10:  # Many CORS endpoints failed
            anomalies.append({
                'component': 'CORS Configuration',
                'description': f'Unable to analyze CORS on {len(cors_errors)} endpoints due to connection issues',
                'severity': 'medium',
                'recommendation': 'Fix underlying connection issues to properly assess CORS security',
                'score': 0.6
            })
        
        return anomalies

    def detect_anomalies(self, scan_data):
        print(f"DEBUG: scan_data = {type(scan_data)} with {len(scan_data) if hasattr(scan_data, '__len__') else 'no length'}")
        """Enhanced anomaly detection including scan failures"""
        # Try existing detection methods first
        if isinstance(scan_data, dict):
            base_result = self._detect_with_statistics(scan_data)
            
            # ADD NEW ENHANCEMENTS HERE
            # Get smart thresholds for this scan
            self.smart_thresholds = self._get_smart_thresholds(scan_data)
            
            # Add behavioral anomalies to existing results
            behavioral_anomalies = self._detect_behavioral_patterns(scan_data)
            base_result['anomalies'].extend(behavioral_anomalies)
            
            # Add infrastructure anomalies
            infra_anomalies = self._detect_infrastructure_patterns(scan_data)
            base_result['anomalies'].extend(infra_anomalies)
            
            # Add security pattern anomalies
            security_anomalies = self._detect_security_patterns(scan_data)
            base_result['anomalies'].extend(security_anomalies)
            
            # Recalculate anomaly score with new findings
            if base_result['anomalies']:
                total_score = sum(a.get('score', 0.5) for a in base_result['anomalies'])
                base_result['anomaly_score'] = min(1.0, total_score / len(base_result['anomalies']))
                base_result['is_anomaly'] = base_result['anomaly_score'] > self.threshold
            
            return base_result
        
        # If scan_data is actually scan results (from a failed scan)
        # Detect anomalies from the scan failures themselves
        if hasattr(scan_data, 'filter') or isinstance(scan_data, list):
            failure_anomalies = self.detect_scan_failure_anomalies(scan_data)
            
            return {
                'is_anomaly': len(failure_anomalies) > 0,
                'anomaly_score': 1.0 if failure_anomalies else 0.0,
                'model_based': False,
                'anomalies': failure_anomalies
            }
        
        # Fallback to existing logic
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
        
        self._check_coordinated_patterns(scan_data, anomalies)
        self._check_temporal_patterns(scan_data, anomalies)
        
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
            threshold = self.smart_thresholds.get('response_time', 2.0)
            if response_time > threshold:  # Arbitrary threshold

                severity = 'critical' if response_time > threshold * 3 else 'high' if response_time > threshold * 2 else 'medium'

                anomalies.append({
                    'component': 'Response Time',
                    'description': f'Response time {response_time:.2f}s exceeds adaptive threshold {threshold:.2f}s',
                    'severity': severity,
                    'recommendation': f'Optimize server response time. Current: {response_time:.2f}s, Target: <{threshold:.1f}s',
                    'score': min(1.0, response_time / (threshold * 2))
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
        # ADD NEW PERFORMANCE CHECKS
        # Time to First Byte analysis
        if 'time_to_first_byte' in performance_data:
            ttfb = performance_data['time_to_first_byte']
            if ttfb > 1.0:  # TTFB over 1 second is concerning
                anomalies.append({
                    'component': 'Time to First Byte',
                    'description': f'High TTFB indicates server processing delays: {ttfb:.2f}s',
                    'severity': 'medium',
                    'recommendation': 'Optimize server processing, database queries, or implement server-side caching',
                    'score': min(1.0, ttfb / 3.0)
                })
        
        # Resource loading failures
        if 'failed_resources' in performance_data and 'total_resources' in performance_data:
            failed = performance_data['failed_resources']
            total = performance_data['total_resources']
            if failed > 0 and total > 0:
                failure_rate = failed / total
                if failure_rate > 0.05:  # More than 5% failure
                    anomalies.append({
                        'component': 'Resource Loading',
                        'description': f'{failed}/{total} resources failed to load ({failure_rate:.1%})',
                        'severity': 'high' if failure_rate > 0.15 else 'medium',
                        'recommendation': 'Fix broken resource links and improve CDN reliability',
                        'score': min(1.0, failure_rate * 2)
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
        security_headers = {
        'strict-transport-security': {'severity': 'high', 'description': 'HSTS header prevents protocol downgrade attacks'},
        'content-security-policy': {'severity': 'high', 'description': 'CSP header prevents XSS and injection attacks'},
        'x-content-type-options': {'severity': 'medium', 'description': 'Prevents MIME type sniffing attacks'},
        'x-frame-options': {'severity': 'medium', 'description': 'Prevents clickjacking attacks'},
        'referrer-policy': {'severity': 'low', 'description': 'Controls referrer information leakage'}
    }
    
        missing_security = []
        for header, info in security_headers.items():
            if header not in headers:
                missing_security.append((header, info))
        
        if missing_security:
            for header, info in missing_security[:3]:  # Top 3 missing
                anomalies.append({
                    'component': 'Missing Security Header',
                    'description': f'Missing {header} header: {info["description"]}',
                    'severity': info['severity'],
                    'recommendation': f'Implement {header} header for enhanced security',
                    'score': 0.8 if info['severity'] == 'high' else 0.6 if info['severity'] == 'medium' else 0.4
                })
        
        # Check for unusual header values
        if 'server' in headers:
            server_value = headers['server'].lower()
            development_servers = ['werkzeug', 'django', 'express development']
            if any(dev_server in server_value for dev_server in development_servers):
                anomalies.append({
                    'component': 'Development Server',
                    'description': f'Development server detected in production: {headers["server"]}',
                    'severity': 'high',
                    'recommendation': 'Replace with production-grade web server (nginx, apache, etc.)',
                    'score': 0.9
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
    def _get_smart_thresholds(self, scan_data):
        """Calculate smart thresholds based on scan context"""
        thresholds = {
            'response_time': 2.0,
            'page_size': 3000000,
            'header_count': 20
        }
        
        # Adjust based on detected website type
        content = scan_data.get('content', {})
        url = scan_data.get('url', '')
        
        # E-commerce sites should be faster
        if any(keyword in content.get('text', '').lower() for keyword in ['cart', 'checkout', 'payment', 'buy']):
            thresholds['response_time'] = 1.5
        
        # API endpoints should be much faster
        if '/api/' in url or 'api.' in url:
            thresholds['response_time'] = 0.8
            thresholds['header_count'] = 15
        
        # Static sites can be more lenient
        if any(keyword in content.get('text', '').lower() for keyword in ['blog', 'portfolio', 'landing']):
            thresholds['response_time'] = 3.0
            thresholds['page_size'] = 5000000
        
        return thresholds

    def _detect_behavioral_patterns(self, scan_data):
        """Detect behavioral anomalies"""
        anomalies = []
        
        # Compare with historical data if available
        historical = self._get_historical_baseline()
        if historical:
            current_response = scan_data.get('performance', {}).get('response_time', 0)
            avg_response = historical.get('avg_response_time', 0)
            
            if current_response > avg_response * 2:  # 100% slower than average
                anomalies.append({
                    'component': 'Performance Degradation',
                    'description': f'Response time ({current_response:.2f}s) is {((current_response/avg_response - 1) * 100):.0f}% slower than historical average',
                    'severity': 'high',
                    'recommendation': 'Investigate recent changes that may have impacted performance',
                    'score': min(1.0, current_response / (avg_response * 3))
                })
        
        return anomalies

    def _detect_infrastructure_patterns(self, scan_data):
        """Detect infrastructure anomalies"""
        anomalies = []
        headers = scan_data.get('headers', {})
        
        # Check for load balancer inconsistencies
        has_forwarded = 'x-forwarded-for' in headers
        has_real_ip = 'x-real-ip' in headers
        
        if has_forwarded and not has_real_ip:
            anomalies.append({
                'component': 'Load Balancer Configuration',
                'description': 'Inconsistent proxy headers detected',
                'severity': 'medium',
                'recommendation': 'Review load balancer configuration for proper header handling',
                'score': 0.6
            })
        
        return anomalies

    def _detect_security_patterns(self, scan_data):
        """Detect security pattern anomalies"""
        anomalies = []
        headers = scan_data.get('headers', {})
        
        # Check for multiple authentication methods
        auth_headers = [h for h in headers.keys() if 'auth' in h.lower()]
        if len(auth_headers) > 2:
            anomalies.append({
                'component': 'Authentication Complexity',
                'description': f'Multiple authentication mechanisms detected: {", ".join(auth_headers)}',
                'severity': 'medium',
                'recommendation': 'Simplify authentication architecture',
                'score': 0.7
            })
        
        return anomalies

    def _check_coordinated_patterns(self, scan_data, anomalies):
        """Check for coordinated attack patterns"""
        # Check for bot-like behavior indicators
        headers = scan_data.get('headers', {})
        user_agent = headers.get('user-agent', '').lower()
        
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper']
        if any(indicator in user_agent for indicator in bot_indicators):
            anomalies.append({
                'component': 'Bot Detection',
                'description': f'Bot user agent detected: {headers.get("user-agent", "")}',
                'severity': 'low',
                'recommendation': 'Monitor for automated scanning attempts',
                'score': 0.4
            })

    def _check_temporal_patterns(self, scan_data, anomalies):
        """Check for time-based anomalies"""
        from datetime import datetime
        
        # Check if this is an unusual time for activity
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Very early or very late
            anomalies.append({
                'component': 'Unusual Timing',
                'description': f'Activity detected during off-hours: {current_hour:02d}:00',
                'severity': 'low',
                'recommendation': 'Monitor for potential automated attacks during off-hours',
                'score': 0.3
            })

    def _get_historical_baseline(self):
        """Get historical baseline data for comparison"""
        # This would query your database for historical data
        # For now, return None to avoid breaking existing functionality
        try:
            # You could implement this to query your ScanResult model
            # for historical averages
            return None
        except:
            return None
    
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