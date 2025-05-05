# backend/ai_analyzer/services/ai_analysis.py

import logging
import time
import traceback
from ..models import AIAnalysis, AIRecommendation
from scanner.models import ScanResult
from integrations.shodan_service import ShodanService
from ai_analyzer.services.threat_intelligence import ThreatIntelligence

# Set up more detailed logging
logger = logging.getLogger(__name__)

class AIAnalysisService:
    """Service for performing AI-based security analysis with improved error handling"""
    
    def __init__(self, scan):
        self.scan = scan
        self.start_time = time.time()
        
        # Initialize external services
        self.threat_intel = ThreatIntelligence()
        self.shodan = ShodanService()
    
    def analyze(self):
        """Run all AI analyses on the scan results with detailed logging"""
        logger.info(f"Starting AI analysis for scan {self.scan.id}")
        
        try:
            # Log scan details
            logger.info(f"Scan details: target_url={self.scan.target_url}, scan_types={self.scan.scan_types}")
            
            # Get external threat intelligence data
            try:
                logger.info(f"Getting external threat intelligence for {self.scan.target_url}")
                domain_intel = self.threat_intel.analyze_domain(self.scan.target_url)
                ports_info = self.shodan.get_ports(self.scan.target_url)
                
                # Log summary of external data
                logger.info(f"Domain intelligence found: {domain_intel is not None}")
                logger.info(f"Ports information found: {ports_info is not None}")
            except Exception as e:
                logger.error(f"Error retrieving external threat intelligence: {str(e)}")
                logger.error(traceback.format_exc())
                # Continue with analysis even if external data retrieval fails
            
            # Get all scan results
            scan_results = ScanResult.objects.filter(scan=self.scan)
            
            # Log scan results count
            result_count = scan_results.count()
            logger.info(f"Found {result_count} scan results for analysis")
            
            # If no results, return early
            if result_count == 0:
                logger.warning(f"No scan results found for scan {self.scan.id}")
                
                # Create an empty analysis to indicate we processed it
                AIAnalysis.objects.create(
                    user=self.scan.user,
                    scan_id=str(self.scan.id),
                    scan_identifier=self.scan.target_url,
                    analysis_type='no_data',
                    analysis_result={'error': 'No scan results found to analyze'},
                    confidence_score=0
                )
                return
            
            # Log categories found
            categories = scan_results.values_list('category', flat=True).distinct()
            logger.info(f"Categories found in scan results: {list(categories)}")
            
            # Create a single analysis record for this scan (to prevent duplicate scan_id issues)
            analysis = AIAnalysis.objects.create(
                user=self.scan.user,
                scan_id=str(self.scan.id),
                scan_identifier=self.scan.target_url,
                analysis_type='combined',
                analysis_result={
                    'threat_detection': {},
                    'anomaly_detection': {},
                    'risk_scoring': {},
                    'external_intelligence': {
                        'domain_intel': domain_intel if 'domain_intel' in locals() else {},
                        'ports_info': ports_info if 'ports_info' in locals() else {}
                    }
                },
                confidence_score=0.85
            )
            
            # Run threat detection
            logger.info("Starting threat detection analysis")
            try:
                threat_results = self._run_threat_detection(scan_results, analysis)
                logger.info("Threat detection completed successfully")
                
                # Update analysis with threat results
                analysis.analysis_result['threat_detection'] = threat_results
                analysis.save()
            except Exception as e:
                logger.error(f"Error in threat detection: {str(e)}")
                logger.error(traceback.format_exc())
                # Continue with other analyses even if this one fails
            
            # Run anomaly detection
            logger.info("Starting anomaly detection analysis")
            try:
                anomaly_results = self._run_anomaly_detection(scan_results, analysis)
                logger.info("Anomaly detection completed successfully")
                
                # Update analysis with anomaly results
                analysis.analysis_result['anomaly_detection'] = anomaly_results
                analysis.save()
            except Exception as e:
                logger.error(f"Error in anomaly detection: {str(e)}")
                logger.error(traceback.format_exc())
                # Continue with other analyses even if this one fails
            
            # Run risk scoring
            logger.info("Starting risk scoring analysis")
            try:
                risk_results = self._run_risk_scoring(scan_results, analysis)
                logger.info("Risk scoring completed successfully")
                
                # Update analysis with risk scoring results
                analysis.analysis_result['risk_scoring'] = risk_results
                analysis.save()
            except Exception as e:
                logger.error(f"Error in risk scoring: {str(e)}")
                logger.error(traceback.format_exc())
            
            # Update confidence score based on all analyses
            try:
                # Assign the highest confidence score from all analyses
                confidence_scores = [
                    analysis.analysis_result.get('threat_detection', {}).get('confidence', 0),
                    analysis.analysis_result.get('anomaly_detection', {}).get('confidence', 0),
                    analysis.analysis_result.get('risk_scoring', {}).get('confidence', 0.85)
                ]
                analysis.confidence_score = max(confidence_scores)
                analysis.save()
            except Exception as e:
                logger.error(f"Error updating confidence score: {str(e)}")
            
            # Log completion time
            elapsed_time = time.time() - self.start_time
            logger.info(f"Completed AI analysis for scan {self.scan.id} in {elapsed_time:.2f} seconds")
            
        except Exception as e:
            logger.exception(f"Critical error in AI analysis for scan {self.scan.id}: {str(e)}")
            
            # Create an error analysis entry so frontend knows analysis attempted but failed
            try:
                # Check if we already have an analysis record for this scan
                existing_analysis = AIAnalysis.objects.filter(scan_id=str(self.scan.id)).first()
                
                if existing_analysis:
                    # Update existing analysis with error info
                    existing_analysis.analysis_result = {
                        'error': str(e),
                        'traceback': traceback.format_exc()
                    }
                    existing_analysis.save()
                else:
                    # Create new analysis with error info
                    AIAnalysis.objects.create(
                        user=self.scan.user,
                        scan_id=str(self.scan.id),
                        scan_identifier=self.scan.target_url,
                        analysis_type='error',
                        analysis_result={'error': str(e), 'traceback': traceback.format_exc()},
                        confidence_score=0
                    )
            except Exception as inner_e:
                logger.error(f"Failed to create error analysis record: {str(inner_e)}")
            
            raise
    
    def _run_threat_detection(self, scan_results, analysis):
        """Run threat detection analysis with better error handling"""
        try:
            # Log start of specific analysis
            logger.info(f"Preparing data for threat detection analysis")
            
            # Prepare data for threat detection
            headers_data = []
            for result in scan_results.filter(category='headers'):
                try:
                    headers_data.append(result.details)
                except Exception as e:
                    logger.warning(f"Error processing header result {result.id}: {str(e)}")
            
            # Log headers data count
            logger.info(f"Processing {len(headers_data)} header results")
            
            # No header data to analyze
            if not headers_data:
                logger.info("No header data found for threat detection")
                return {'threat_count': 0, 'threats': [], 'confidence': 0.5}
            
            # Perform threat detection
            logger.info("Performing threat detection analysis")
            threat_results = self._detect_threats(headers_data)
            
            # Log threat detection results
            logger.info(f"Found {threat_results.get('threat_count', 0)} potential threats")
            
            # Generate recommendations based on threats
            logger.info("Generating threat-based recommendations")
            recs_created = 0
            for threat in threat_results.get('threats', []):
                try:
                    AIRecommendation.objects.create(
                        analysis=analysis,
                        title=f"Detected {threat['type']} threat",
                        description=threat['description'],
                        severity=threat['severity'],
                        recommendation=threat['mitigation'],
                        recommendation_type='security',
                        confidence_score=threat['confidence']
                    )
                    recs_created += 1
                except Exception as e:
                    logger.error(f"Error creating recommendation for threat {threat['type']}: {str(e)}")
            
            logger.info(f"Created {recs_created} threat recommendations")
            
            # Add confidence to the results
            threat_results['confidence'] = 0.85 if threat_results.get('threats') else 0.5
            
            return threat_results
                
        except Exception as e:
            logger.exception(f"Error in threat detection: {str(e)}")
            raise
    
    def _run_anomaly_detection(self, scan_results, analysis):
        """Run anomaly detection analysis with better error handling"""
        try:
            logger.info("Preparing data for anomaly detection analysis")
            
            # Extract data for anomaly detection
            ssl_data = []
            for result in scan_results.filter(category='ssl'):
                try:
                    ssl_data.append(result.details)
                except Exception as e:
                    logger.warning(f"Error processing SSL result {result.id}: {str(e)}")
            
            # Log SSL data count
            logger.info(f"Processing {len(ssl_data)} SSL results")
            
            # No SSL data to analyze
            if not ssl_data:
                logger.info("No SSL data found for anomaly detection")
                return {'anomaly_count': 0, 'anomalies': [], 'confidence': 0.5}
            
            # Perform anomaly detection
            logger.info("Performing anomaly detection analysis")
            anomaly_results = self._detect_anomalies(ssl_data)
            
            # Log anomaly detection results
            logger.info(f"Found {anomaly_results.get('anomaly_count', 0)} potential anomalies")
            
            # Generate recommendations for anomalies
            logger.info("Generating anomaly-based recommendations")
            recs_created = 0
            for anomaly in anomaly_results.get('anomalies', []):
                try:
                    AIRecommendation.objects.create(
                        analysis=analysis,
                        title=f"Detected anomaly in {anomaly['component']}",
                        description=anomaly['description'],
                        severity=anomaly['severity'],
                        recommendation=anomaly['recommendation'],
                        recommendation_type='security',
                        confidence_score=anomaly['score']
                    )
                    recs_created += 1
                except Exception as e:
                    logger.error(f"Error creating recommendation for anomaly in {anomaly['component']}: {str(e)}")
            
            logger.info(f"Created {recs_created} anomaly recommendations")
            
            # Add confidence to the results
            anomaly_results['confidence'] = 0.85 if anomaly_results.get('anomalies') else 0.5
            
            return anomaly_results
                
        except Exception as e:
            logger.exception(f"Error in anomaly detection: {str(e)}")
            raise
    
    def _run_risk_scoring(self, scan_results, analysis):
        """Run risk scoring analysis with better error handling"""
        try:
            logger.info("Preparing data for risk scoring analysis")
            
            # Collect all results for risk scoring
            all_data = {}
            for result in scan_results:
                try:
                    if result.category not in all_data:
                        all_data[result.category] = []
                    all_data[result.category].append({
                        'name': result.name,
                        'severity': result.severity,
                        'details': result.details
                    })
                except Exception as e:
                    logger.warning(f"Error processing result {result.id} for risk scoring: {str(e)}")
            
            # Log category counts
            for category, items in all_data.items():
                logger.info(f"Category '{category}': {len(items)} items")
            
            # Calculate risk score
            logger.info("Calculating risk scores")
            risk_results = self._calculate_risk_score(all_data)
            
            # Log risk scoring results
            logger.info(f"Overall security score: {risk_results.get('overall_score', 0)}/100")
            
            # Generate overall recommendation
            logger.info("Generating overall risk recommendation")
            try:
                AIRecommendation.objects.create(
                    analysis=analysis,
                    title=f"Overall Security Assessment",
                    description=f"The security score for {self.scan.target_url} is {risk_results['overall_score']}/100",
                    severity=self._get_severity_from_score(risk_results['overall_score']),
                    recommendation=risk_results['improvement_suggestions'],
                    recommendation_type='summary',
                    confidence_score=0.95
                )
                logger.info("Created overall risk recommendation")
            except Exception as e:
                logger.error(f"Error creating overall risk recommendation: {str(e)}")
            
            # Add confidence to the results
            risk_results['confidence'] = 0.95
            
            return risk_results
                
        except Exception as e:
            logger.exception(f"Error in risk scoring: {str(e)}")
            raise
    
    def _detect_threats(self, headers_data):
        """Detect security threats in headers data"""
        # This would be more sophisticated in a real implementation
        threats = []
        
        for header_item in headers_data:
            # Missing security headers
            recommendation = header_item.get('recommendation', '')
            description = header_item.get('description', '')
            
            if 'Content-Security-Policy' in description:
                threats.append({
                    'type': 'XSS',
                    'description': 'Potential Cross-Site Scripting vulnerability due to missing Content-Security-Policy header.',
                    'severity': 'high',
                    'mitigation': 'Implement a strict Content-Security-Policy header to prevent XSS attacks.',
                    'confidence': 0.85
                })
            
            if 'Strict-Transport-Security' in description:
                threats.append({
                    'type': 'Protocol Downgrade',
                    'description': 'Potential protocol downgrade attacks due to missing HSTS header.',
                    'severity': 'medium',
                    'mitigation': 'Implement Strict-Transport-Security header with a long max-age value.',
                    'confidence': 0.80
                })
            
            if 'X-Frame-Options' in description:
                threats.append({
                    'type': 'Clickjacking',
                    'description': 'Potential clickjacking vulnerability due to missing X-Frame-Options header.',
                    'severity': 'medium',
                    'mitigation': 'Implement X-Frame-Options header with DENY or SAMEORIGIN value.',
                    'confidence': 0.90
                })
        
        return {
            'threats': threats,
            'threat_count': len(threats)
        }
    
    def _detect_anomalies(self, ssl_data):
        """Detect anomalies in SSL configuration"""
        # This would be more sophisticated in a real implementation
        anomalies = []
        
        for ssl_item in ssl_data:
            # Check for weak cipher suites
            if 'cipher_suite' in ssl_item and 'weak' in ssl_item.get('cipher_suite', '').lower():
                anomalies.append({
                    'component': 'SSL Cipher Suites',
                    'description': 'Detected weak cipher suites in SSL/TLS configuration.',
                    'severity': 'high',
                    'recommendation': 'Disable weak cipher suites and use only strong encryption.',
                    'score': 0.92
                })
            
            # Check for outdated SSL/TLS versions
            if 'current_protocol' in ssl_item and ssl_item.get('current_protocol') in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                anomalies.append({
                    'component': 'SSL/TLS Protocol',
                    'description': 'Detected outdated SSL/TLS protocol version.',
                    'severity': 'high',
                    'recommendation': 'Update to TLSv1.2 or TLSv1.3 and disable older protocols.',
                    'score': 0.95
                })
            
            # Check for certificate expiration
            if 'expiry_date' in ssl_item and 'days_until_expiry' in ssl_item:
                days = ssl_item.get('days_until_expiry', 0)
                if days < 30:
                    anomalies.append({
                        'component': 'SSL Certificate',
                        'description': f'SSL certificate will expire in {days} days.',
                        'severity': 'medium' if days > 7 else 'high',
                        'recommendation': 'Renew the SSL certificate before it expires.',
                        'score': 0.98
                    })
        
        return {
            'anomalies': anomalies,
            'anomaly_count': len(anomalies)
        }
    
    def _calculate_risk_score(self, all_data):
        """Calculate overall security risk score"""
        # This would be more sophisticated in a real implementation
        
        # Initialize scores by category
        category_scores = {
            'headers': 0,
            'ssl': 0,
            'vulnerabilities': 0,
            'content': 0
        }
        
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Process findings
        for category, findings in all_data.items():
            if category not in category_scores:
                continue
                
            # Calculate category score based on severity
            score = 100  # Start with perfect score
            for finding in findings:
                severity = finding['severity']
                severity_counts[severity] += 1
                
                # Deduct points based on severity
                if severity == 'critical':
                    score -= 25
                elif severity == 'high':
                    score -= 15
                elif severity == 'medium':
                    score -= 10
                elif severity == 'low':
                    score -= 5
            
            # Ensure score is between 0 and 100
            category_scores[category] = max(0, min(100, score))
        
        # Calculate overall score (weighted average)
        weights = {
            'headers': 0.25,
            'ssl': 0.30,
            'vulnerabilities': 0.35,
            'content': 0.10
        }
        
        overall_score = 0
        total_weight = 0
        
        for category, score in category_scores.items():
            if category in all_data:  # Only include categories with data
                weight = weights[category]
                overall_score += score * weight
                total_weight += weight
        
        # Normalize score
        if total_weight > 0:
            overall_score = overall_score / total_weight
        
        # Generate improvement suggestions
        suggestions = self._generate_improvement_suggestions(category_scores, severity_counts)
        
        return {
            'overall_score': round(overall_score),
            'category_scores': category_scores,
            'severity_counts': severity_counts,
            'improvement_suggestions': suggestions
        }
    
    def _generate_improvement_suggestions(self, category_scores, severity_counts):
        """Generate improvement suggestions based on scores"""
        suggestions = []
        
        # Add category-specific suggestions
        for category, score in category_scores.items():
            if score < 60:
                if category == 'headers':
                    suggestions.append("Implement secure HTTP headers including Content-Security-Policy, Strict-Transport-Security, and X-Content-Type-Options")
                elif category == 'ssl':
                    suggestions.append("Upgrade SSL/TLS configuration to use only TLSv1.2+, strong cipher suites, and proper certificate validation")
                elif category == 'vulnerabilities':
                    suggestions.append("Address high-risk vulnerabilities in web application code and server configuration")
                elif category == 'content':
                    suggestions.append("Review website content for security risks and sensitive information exposure")
        
        # Add general suggestions based on severity counts
        if severity_counts['critical'] > 0:
            suggestions.append(f"Address {severity_counts['critical']} critical issues immediately as they pose immediate security risks")
        
        if severity_counts['high'] > 0:
            suggestions.append(f"Prioritize fixing {severity_counts['high']} high severity issues in your next development cycle")
        
        # If no specific suggestions, add general advice
        if not suggestions:
            suggestions.append("Continue monitoring your site security regularly with periodic scans")
        
        return "\n• ".join([""] + suggestions)
    
    def _get_severity_from_score(self, score):
        """Convert a numerical score to a severity rating"""
        if score < 50:
            return 'critical'
        elif score < 70:
            return 'high'
        elif score < 85:
            return 'medium'
        elif score < 95:
            return 'low'
        else:
            return 'info'