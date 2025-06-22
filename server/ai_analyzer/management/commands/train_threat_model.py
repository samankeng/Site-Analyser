# Create this file: ai_analyzer/management/commands/train_threat_model.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from scanner.models import ScanResult, Scan
from ai_analyzer.ml.threat_detection.model import ThreatDetectionModel
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Train the threat detection ML model with historical scan data'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--min-scans',
            type=int,
            default=50,
            help='Minimum number of scan results required for training (default: 50)'
        )
        parser.add_argument(
            '--max-scans',
            type=int,
            default=1000,
            help='Maximum number of scan results to use for training (default: 1000)'
        )
        parser.add_argument(
            '--threat-threshold',
            type=float,
            default=0.6,
            help='Threshold for labeling results as threats - lower = more threats (default: 0.6)'
        )
        parser.add_argument(
            '--test-model',
            action='store_true',
            help='Test the model after training'
        )
    
    def handle(self, *args, **options):
        self.stdout.write("🚀 Starting Threat Detection Model Training")
        self.stdout.write("=" * 60)
        
        min_scans = options['min_scans']
        max_scans = options['max_scans']
        threat_threshold = options['threat_threshold']
        test_model = options['test_model']
        
        # Step 1: Check available data
        self.stdout.write("📊 Checking available scan data...")
        total_results = ScanResult.objects.count()
        self.stdout.write(f"   Total scan results available: {total_results}")
        
        if total_results < min_scans:
            self.stdout.write(
                self.style.ERROR(f"❌ Not enough scan results. Found {total_results}, need at least {min_scans}")
            )
            self.stdout.write("   💡 Run more scans first, then try training again")
            return
        
        # Step 2: Collect training data
        self.stdout.write(f"📦 Collecting training data...")
        self.stdout.write(f"   Using up to {max_scans} most recent scan results")
        self.stdout.write(f"   Threat labeling threshold: {threat_threshold}")
        
        training_data = self.collect_training_data(min_scans, max_scans, threat_threshold)
        
        if not training_data:
            self.stdout.write(self.style.ERROR("❌ Failed to collect training data"))
            return
        
        # Step 3: Train the model
        self.stdout.write("🤖 Training threat detection model...")
        self.stdout.write("   This may take a few minutes...")
        
        threat_model = ThreatDetectionModel()
        success = threat_model.train_model(training_data)
        
        if success:
            self.stdout.write(self.style.SUCCESS("✅ Threat detection model trained successfully!"))
            self.stdout.write(f"📁 Model saved to: {threat_model.model_path}")
            
            # Step 4: Verify the model loads correctly
            self.stdout.write("🔍 Verifying model...")
            threat_model_test = ThreatDetectionModel()
            
            if threat_model_test.model is not None:
                self.stdout.write(self.style.SUCCESS("✅ Model verification passed!"))
                self.stdout.write(self.style.SUCCESS("🎉 ML-based threat detection is now ACTIVE!"))
                
                # Step 5: Test the model if requested
                if test_model:
                    self.stdout.write("🧪 Testing model with sample data...")
                    self.test_trained_model(threat_model_test)
                    
            else:
                self.stdout.write(self.style.WARNING("⚠️ Model saved but not loading correctly"))
                self.stdout.write("   Check the model file and try reloading")
        else:
            self.stdout.write(self.style.ERROR("❌ Model training failed"))
            self.stdout.write("   Check the logs for more details")
    
    def collect_training_data(self, min_scans, max_scans, threat_threshold):
        """Collect and label historical scan data for training"""
        try:
            # Get recent scan results with variety
            self.stdout.write(f"   Querying database for scan results...")
            scan_results = ScanResult.objects.select_related('scan').order_by('-created_at')[:max_scans]
            
            actual_count = scan_results.count()
            self.stdout.write(f"   Retrieved {actual_count} scan results")
            
            if actual_count < min_scans:
                self.stdout.write(
                    self.style.ERROR(f"❌ Not enough scan results. Found {actual_count}, need {min_scans}")
                )
                return None
            
            threat_model = ThreatDetectionModel()
            features = []
            labels = []
            
            self.stdout.write(f"   Processing scan results for feature extraction...")
            
            categories_seen = set()
            severities_seen = set()
            
            for i, result in enumerate(scan_results):
                if i % 200 == 0 and i > 0:
                    self.stdout.write(f"     Processed {i} results...")
                
                # Track variety
                categories_seen.add(result.category)
                severities_seen.add(result.severity)
                
                # Extract features
                feature_vector = threat_model._extract_features_for_training(result)
                features.append(feature_vector)
                
                # Create labels based on severity and patterns
                label = self.create_threat_label(result, threat_threshold)
                labels.append(label)
            
            # Analyze dataset balance
            positive_count = sum(labels)
            negative_count = len(labels) - positive_count
            balance_ratio = positive_count / len(labels) if len(labels) > 0 else 0
            
            self.stdout.write(f"📈 Dataset Analysis:")
            self.stdout.write(f"   Total samples: {len(labels)}")
            self.stdout.write(f"   Threat samples (positive): {positive_count}")
            self.stdout.write(f"   Non-threat samples (negative): {negative_count}")
            self.stdout.write(f"   Balance ratio: {balance_ratio:.2%}")
            self.stdout.write(f"   Categories found: {', '.join(sorted(categories_seen))}")
            self.stdout.write(f"   Severities found: {', '.join(sorted(severities_seen))}")
            
            # Warn about dataset issues
            if positive_count < 5:
                self.stdout.write(self.style.WARNING("⚠️ Very few threat examples - consider lowering threat threshold"))
            
            if balance_ratio < 0.1:
                self.stdout.write(self.style.WARNING("⚠️ Dataset heavily imbalanced - model may not train optimally"))
            elif balance_ratio > 0.9:
                self.stdout.write(self.style.WARNING("⚠️ Too many threats labeled - consider raising threat threshold"))
            else:
                self.stdout.write(self.style.SUCCESS("✅ Dataset balance looks good"))
            
            return {
                'features': features,
                'labels': labels,
                'feature_names': threat_model.feature_names,
                'metadata': {
                    'total_samples': len(labels),
                    'positive_samples': positive_count,
                    'negative_samples': negative_count,
                    'balance_ratio': balance_ratio,
                    'categories': list(categories_seen),
                    'severities': list(severities_seen),
                    'threat_threshold': threat_threshold
                }
            }
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error collecting training data: {str(e)}"))
            logger.exception("Error in collect_training_data")
            return None
    
    def create_threat_label(self, scan_result, threshold):
        """Create threat label for a scan result (1 = threat, 0 = no threat)"""
        
        # Get result attributes safely
        severity = getattr(scan_result, 'severity', 'info')
        category = getattr(scan_result, 'category', '')
        name = getattr(scan_result, 'name', '').lower()
        description = getattr(scan_result, 'description', '').lower()
        
        threat_score = 0.0
        
        # 1. Severity-based scoring (primary factor)
        severity_scores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.4,
            'low': 0.2,
            'info': 0.1
        }
        threat_score += severity_scores.get(severity.lower() if severity else 'info', 0.1)
        
        # 2. Category-based scoring 
        category_weights = {
            'ssl': 0.3,           # SSL issues are serious
            'headers': 0.2,       # Security header issues
            'vulnerabilities': 0.4, # Direct vulnerabilities
            'content': 0.1,       # Content issues
            'performance': 0.05   # Performance issues (usually not threats)
        }
        threat_score += category_weights.get(category, 0.1)
        
        # 3. Keyword-based scoring (threat indicators)
        threat_keywords = {
            'high_risk': ['xss', 'injection', 'csrf', 'clickjacking', 'expired', 'vulnerability'],
            'medium_risk': ['weak', 'missing', 'insecure', 'deprecated', 'outdated'],
            'low_risk': ['warning', 'recommendation', 'improvement']
        }
        
        text_content = name + ' ' + description
        
        for keyword in threat_keywords['high_risk']:
            if keyword in text_content:
                threat_score += 0.2
                break  # Only count once
        
        for keyword in threat_keywords['medium_risk']:
            if keyword in text_content:
                threat_score += 0.1
                break
        
        # 4. Security pattern detection
        security_patterns = [
            'certificate', 'authentication', 'authorization', 'encryption',
            'protocol', 'cipher', 'hash', 'signature'
        ]
        
        if any(pattern in text_content for pattern in security_patterns):
            threat_score += 0.1
        
        # 5. Normalize and apply threshold
        threat_score = min(threat_score, 1.0)  # Cap at 1.0
        
        return 1 if threat_score >= threshold else 0
    
    def test_trained_model(self, threat_model):
        """Test the trained model with sample scenarios"""
        try:
            test_scenarios = [
                {
                    'name': 'High-Risk SSL Issue',
                    'data': {
                        'headers': {},
                        'ssl': {'certificate': {'expired': True}},
                        'content': {},
                        'performance': {}
                    }
                },
                {
                    'name': 'Missing Security Headers',
                    'data': {
                        'headers': {'Content-Type': 'text/html'},  # Missing security headers
                        'ssl': {},
                        'content': {},
                        'performance': {}
                    }
                },
                {
                    'name': 'Normal Configuration',
                    'data': {
                        'headers': {
                            'Content-Security-Policy': 'default-src self',
                            'X-Frame-Options': 'DENY'
                        },
                        'ssl': {'grade': 'A'},
                        'content': {},
                        'performance': {'response_time': 0.5}
                    }
                }
            ]
            
            self.stdout.write("   Test Results:")
            for scenario in test_scenarios:
                result = threat_model.detect_threats(scenario['data'])
                
                threat_detected = result.get('threat_detected', False)
                threat_score = result.get('threat_score', 0)
                model_based = result.get('model_based', False)
                severity = result.get('severity', 'unknown')
                
                status_icon = "🔴" if threat_detected else "🟢"
                model_icon = "🤖" if model_based else "📋"
                
                self.stdout.write(f"   {status_icon} {scenario['name']}: {model_icon}")
                self.stdout.write(f"      Threat: {threat_detected}, Score: {threat_score:.3f}, Severity: {severity}")
            
            self.stdout.write("")
            if all(threat_model.detect_threats(s['data']).get('model_based', False) for s in test_scenarios):
                self.stdout.write(self.style.SUCCESS("✅ All tests using ML model - training successful!"))
            else:
                self.stdout.write(self.style.WARNING("⚠️ Some tests falling back to rules - check model"))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Model testing failed: {str(e)}"))
            logger.exception("Error in test_trained_model")