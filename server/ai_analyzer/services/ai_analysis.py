# backend/ai_analyzer/services/ai_analysis.py
# COMPLETE WORKING VERSION - Replace your entire ai_analysis.py file with this

import logging
import time
import traceback
import json
import openai
from typing import Dict, List, Any, Optional
from django.conf import settings
from ..models import AIAnalysis, AIRecommendation
from scanner.models import ScanResult
from integrations.shodan_service import ShodanService
from ai_analyzer.services.threat_intelligence import ThreatIntelligence

# Set up more detailed logging
logger = logging.getLogger(__name__)

class EnhancedAIAgent:
    """
    Enhanced AI agent that provides direct, actionable vulnerability remediation advice
    """
    
    def __init__(self):
        # Initialize OpenAI client directly - no more LLMService dependency
        try:
            api_key = getattr(settings, 'OPENAI_API_KEY', None)
            if not api_key:
                logger.error("OPENAI_API_KEY not found in settings")
                self.client = None
            else:
                self.client = openai.OpenAI(api_key=api_key)
                logger.info("OpenAI client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {str(e)}")
            self.client = None
    
    def analyze_scan_results_with_ai(self, scan_results, target_url: str) -> Dict[str, Any]:
        """
        Direct AI analysis of raw scan results for actionable recommendations
        """
        try:
            if not self.client:
                logger.warning("OpenAI client not available, returning fallback response")
                return self._create_fallback_response(scan_results, target_url)
            
            # Format scan results for AI consumption
            formatted_results = self._format_scan_results_for_ai(scan_results, target_url)
            
            # Create structured prompt
            prompt = self._create_comprehensive_prompt(formatted_results)
            
            # Get AI analysis using OpenAI API v1.0+
            ai_response = self._get_llm_response(prompt)
            
            # Parse and structure the response
            return self._parse_ai_remediation_response(ai_response)
            
        except Exception as e:
            logger.exception(f"Error in AI agent analysis: {str(e)}")
            return self._create_fallback_response(scan_results, target_url)
    
    def _get_llm_response(self, prompt: str) -> str:
        """
        Get LLM response using OpenAI API v1.0+
        """
        try:
            logger.info("Requesting AI analysis from OpenAI")
            
            if not self.client:
                raise Exception("OpenAI client not initialized")
            
            # Use new OpenAI API v1.0+
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # or "gpt-4" if you have access
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert providing actionable vulnerability remediation advice. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3
            )
            
            # Extract response using new API format
            ai_response = response.choices[0].message.content
            logger.info(f"Successfully received AI response: {len(ai_response)} characters")
            
            return ai_response
            
        except Exception as e:
            logger.error(f"Error getting LLM response: {str(e)}")
            raise
    
    def _create_fallback_response(self, scan_results, target_url: str) -> Dict[str, Any]:
        """Create a fallback response when AI is unavailable"""
        logger.info("Creating fallback AI response based on scan results")
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        recommendations = []
        
        for result in scan_results:
            severity = result.severity.lower() if result.severity else 'info'
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Create basic recommendations based on scan results
            if result.category == 'headers' and severity in ['high', 'critical']:
                recommendations.append({
                    "issue_name": f"Missing Security Header: {result.name}",
                    "category": "headers",
                    "severity": severity,
                    "risk_assessment": result.description or "Security header missing or misconfigured",
                    "business_impact": "Potential security vulnerabilities that could lead to data breaches",
                    "technical_details": "HTTP security headers help protect against common attacks",
                    "remediation_steps": [
                        "Configure web server to include security headers",
                        "Test header implementation",
                        "Verify headers are properly set"
                    ],
                    "priority": "high" if severity == "critical" else "medium",
                    "estimated_effort": "1-2 hours"
                })
            
            elif result.category == 'ssl' and severity in ['high', 'critical']:
                recommendations.append({
                    "issue_name": f"SSL/TLS Issue: {result.name}",
                    "category": "ssl",
                    "severity": severity,
                    "risk_assessment": result.description or "SSL/TLS configuration issue detected",
                    "business_impact": "Encrypted communications may be compromised",
                    "technical_details": "SSL/TLS configuration needs improvement",
                    "remediation_steps": [
                        "Update SSL/TLS configuration",
                        "Use strong cipher suites",
                        "Test SSL configuration"
                    ],
                    "priority": "high",
                    "estimated_effort": "2-4 hours"
                })
        
        # Calculate basic risk level
        total_critical_high = severity_counts["critical"] + severity_counts["high"]
        if total_critical_high > 5:
            risk_level = "Critical"
        elif total_critical_high > 2:
            risk_level = "High"
        elif severity_counts["medium"] > 10:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "overall_risk_level": risk_level,
            "security_score": max(20, 100 - (severity_counts["critical"] * 15 + severity_counts["high"] * 8)),
            "executive_summary": f"Security analysis completed for {target_url}. Found {sum(severity_counts.values())} total issues.",
            "recommendations": recommendations[:10],  # Limit to top 10
            "quick_wins": [
                "Address critical security headers",
                "Update SSL/TLS configuration",
                "Review and fix high-priority issues"
            ],
            "long_term_strategy": "Implement regular security scanning and monitoring",
            "ai_fallback": True
        }
    
    def _format_scan_results_for_ai(self, scan_results, target_url: str) -> Dict[str, Any]:
        """Format scan results into a structure the AI can easily understand"""
        formatted = {
            "target_url": target_url,
            "scan_timestamp": scan_results.first().created_at.isoformat() if scan_results.exists() else None,
            "findings": {}
        }
        
        # Group findings by category
        for result in scan_results:
            category = result.category
            if category not in formatted["findings"]:
                formatted["findings"][category] = []
            
            formatted["findings"][category].append({
                "name": result.name,
                "severity": result.severity,
                "description": result.description,
                "details": result.details if hasattr(result, 'details') else {}
            })
        
        return formatted
    
    def _create_comprehensive_prompt(self, formatted_results: Dict[str, Any]) -> str:
        """Create a comprehensive prompt for actionable recommendations"""
        # Count total findings by severity
        total_findings = 0
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for category, findings in formatted_results['findings'].items():
            total_findings += len(findings)
            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                if severity in severity_summary:
                    severity_summary[severity] += 1
        
        prompt = f"""
You are a cybersecurity expert analyzing web security scan results. Provide detailed, actionable remediation advice in JSON format.

TARGET: {formatted_results['target_url']}
SCAN DATE: {formatted_results.get('scan_timestamp', 'Unknown')}
TOTAL FINDINGS: {total_findings}

SEVERITY BREAKDOWN:
- Critical: {severity_summary['critical']}
- High: {severity_summary['high']}
- Medium: {severity_summary['medium']}
- Low: {severity_summary['low']}
- Info: {severity_summary['info']}

FINDINGS BY CATEGORY:
{self._format_findings_summary(formatted_results['findings'])}

Please provide a JSON response with this exact structure:
{{
    "overall_risk_level": "Critical|High|Medium|Low",
    "security_score": 0-100,
    "executive_summary": "Brief summary for stakeholders",
    "recommendations": [
        {{
            "issue_name": "Clear name of the security issue",
            "category": "headers|ssl|content|vulnerabilities|configuration",
            "severity": "critical|high|medium|low|info",
            "risk_assessment": "What this vulnerability means and why it's dangerous",
            "business_impact": "How this could affect business operations",
            "technical_details": "Technical explanation for developers",
            "remediation_steps": [
                "Step 1: Specific action to take",
                "Step 2: Another specific action",
                "Step 3: Verification step"
            ],
            "priority": "immediate|high|medium|low",
            "estimated_effort": "30 minutes|2 hours|1 day|1 week"
        }}
    ],
    "quick_wins": [
        "Easy fixes that can be implemented immediately"
    ],
    "long_term_strategy": "Recommendations for ongoing security improvements"
}}

Focus on the most critical issues first and provide specific, actionable steps.
"""
        return prompt
    
    def _format_findings_summary(self, findings: Dict[str, List]) -> str:
        """Format findings for the AI prompt"""
        summary = []
        for category, category_findings in findings.items():
            if category_findings:
                summary.append(f"\n{category.upper()} ({len(category_findings)} findings):")
                for finding in category_findings[:5]:  # Top 5 per category
                    summary.append(f"  - {finding['severity'].upper()}: {finding['name']}")
                if len(category_findings) > 5:
                    summary.append(f"  - ... and {len(category_findings) - 5} more")
        
        return "\n".join(summary) if summary else "No specific findings to display"
    
    def _parse_ai_remediation_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response into structured recommendations"""
        try:
            # Try to extract and parse JSON from response
            json_start = ai_response.find('{')
            json_end = ai_response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                parsed_response = json.loads(json_str)
            else:
                # Try parsing the entire response as JSON
                parsed_response = json.loads(ai_response)
            
            # Validate and add defaults
            parsed_response.setdefault('recommendations', [])
            parsed_response.setdefault('overall_risk_level', 'Medium')
            parsed_response.setdefault('security_score', 50)
            parsed_response.setdefault('executive_summary', 'Security analysis completed')
            
            # Ensure each recommendation has required fields
            for rec in parsed_response['recommendations']:
                rec.setdefault('severity', 'medium')
                rec.setdefault('priority', 'medium')
                rec.setdefault('estimated_effort', 'unknown')
                rec.setdefault('remediation_steps', [])
                rec.setdefault('business_impact', 'Security improvement recommended')
                rec.setdefault('technical_details', 'See remediation steps for details')
            
            logger.info(f"Successfully parsed AI response with {len(parsed_response['recommendations'])} recommendations")
            return parsed_response
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI JSON response: {str(e)}")
            # Return manual parsing fallback
            return self._manual_parse_response(ai_response)
    
    def _manual_parse_response(self, response: str) -> Dict[str, Any]:
        """Manually parse AI response when JSON parsing fails"""
        logger.info("Using manual parsing fallback for AI response")
        
        return {
            "overall_risk_level": "Medium",
            "security_score": 50,
            "executive_summary": "AI analysis completed but required manual parsing",
            "recommendations": [
                {
                    "issue_name": "Manual Review Required",
                    "category": "general",
                    "severity": "medium",
                    "risk_assessment": "AI analysis completed but requires manual review of results",
                    "business_impact": "Security recommendations need manual interpretation",
                    "technical_details": "Review scan findings manually for specific technical details",
                    "remediation_steps": [
                        "Review scan findings manually",
                        "Prioritize critical and high severity issues",
                        "Implement security best practices"
                    ],
                    "priority": "medium",
                    "estimated_effort": "varies"
                }
            ],
            "quick_wins": ["Review and prioritize security findings"],
            "long_term_strategy": "Implement comprehensive security monitoring",
            "manual_parsing_used": True,
            "raw_response_preview": response[:200] + "..." if len(response) > 200 else response
        }


class AIAnalysisService:
    """Service for performing AI-based security analysis with improved error handling"""
    
    def __init__(self, scan):
        self.scan = scan
        self.start_time = time.time()
        
        # Initialize external services
        try:
            self.threat_intel = ThreatIntelligence()
        except:
            self.threat_intel = None
            
        try:
            self.shodan = ShodanService()
        except:
            self.shodan = None
        
        # Initialize enhanced AI agent
        self.enhanced_agent = EnhancedAIAgent()
    
    def analyze(self):
        """Run all AI analyses on the scan results with detailed logging"""
        logger.info(f"Starting AI analysis for scan {self.scan.id}")
        
        try:
            # Get all scan results
            scan_results = ScanResult.objects.filter(scan=self.scan)
            result_count = scan_results.count()
            
            logger.info(f"Found {result_count} scan results for analysis")
            
            if result_count == 0:
                logger.warning(f"No scan results found for scan {self.scan.id}")
                self._create_empty_analysis()
                return
            
            # Create analysis record
            analysis = AIAnalysis.objects.create(
                user=self.scan.user,
                scan_id=str(self.scan.id),
                scan_identifier=self.scan.target_url,
                analysis_type='combined',
                analysis_result={
                    'enhanced_ai_analysis': {},
                    'threat_detection': {},
                    'anomaly_detection': {},
                    'risk_scoring': {}
                },
                confidence_score=0.85
            )
            
            # Run enhanced AI analysis FIRST (most important)
            logger.info("Starting enhanced AI analysis")
            try:
                enhanced_ai_results = self._run_enhanced_ai_analysis(scan_results, analysis)
                analysis.analysis_result['enhanced_ai_analysis'] = enhanced_ai_results
                analysis.save()
                logger.info("Enhanced AI analysis completed successfully")
            except Exception as e:
                logger.error(f"Error in enhanced AI analysis: {str(e)}")
                logger.error(traceback.format_exc())
            
            # Run other analyses
            self._run_other_analyses(scan_results, analysis)
            
            # Update final confidence score
            self._update_confidence_score(analysis)
            
            elapsed_time = time.time() - self.start_time
            logger.info(f"Completed AI analysis for scan {self.scan.id} in {elapsed_time:.2f} seconds")
            
        except Exception as e:
            logger.exception(f"Critical error in AI analysis for scan {self.scan.id}: {str(e)}")
            self._create_error_analysis(str(e))
    
    def _run_enhanced_ai_analysis(self, scan_results, analysis):
        """Enhanced AI analysis that provides direct actionable recommendations"""
        try:
            logger.info("Getting AI-powered recommendations for scan results")
            
            # Get AI-powered recommendations
            ai_recommendations = self.enhanced_agent.analyze_scan_results_with_ai(
                scan_results, 
                self.scan.target_url
            )
            
            # Store enhanced recommendations in database
            if 'recommendations' in ai_recommendations:
                recs_created = 0
                for rec in ai_recommendations['recommendations']:
                    try:
                        # Create recommendation record
                        AIRecommendation.objects.create(
                            analysis=analysis,
                            title=rec.get('issue_name', 'AI Generated Recommendation'),
                            description=rec.get('risk_assessment', rec.get('description', '')),
                            severity=rec.get('severity', 'medium'),
                            recommendation=json.dumps(rec.get('remediation_steps', [])),
                            recommendation_type='ai_enhanced',
                            confidence_score=0.9,
                            metadata={
                                'business_impact': rec.get('business_impact', ''),
                                'technical_details': rec.get('technical_details', ''),
                                'priority': rec.get('priority', 'medium'),
                                'estimated_effort': rec.get('estimated_effort', 'unknown'),
                                'category': rec.get('category', 'general')
                            }
                        )
                        recs_created += 1
                    except Exception as e:
                        logger.error(f"Error creating AI recommendation: {str(e)}")
                
                logger.info(f"Created {recs_created} enhanced AI recommendations")
            
            return ai_recommendations
            
        except Exception as e:
            logger.exception(f"Error in enhanced AI analysis: {str(e)}")
            return {"error": str(e), "recommendations": []}
    
    def _run_other_analyses(self, scan_results, analysis):
        """Run the other analysis methods"""
        try:
            threat_results = self._run_threat_detection(scan_results, analysis)
            analysis.analysis_result['threat_detection'] = threat_results
            analysis.save()
        except Exception as e:
            logger.error(f"Error in threat detection: {str(e)}")
        
        try:
            anomaly_results = self._run_anomaly_detection(scan_results, analysis)
            analysis.analysis_result['anomaly_detection'] = anomaly_results
            analysis.save()
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
        
        try:
            risk_results = self._run_risk_scoring(scan_results, analysis)
            analysis.analysis_result['risk_scoring'] = risk_results
            analysis.save()
        except Exception as e:
            logger.error(f"Error in risk scoring: {str(e)}")
    
    def _update_confidence_score(self, analysis):
        """Update confidence score based on all analyses"""
        try:
            confidence_scores = [
                analysis.analysis_result.get('threat_detection', {}).get('confidence', 0),
                analysis.analysis_result.get('anomaly_detection', {}).get('confidence', 0),
                analysis.analysis_result.get('risk_scoring', {}).get('confidence', 0.85),
                0.9 if analysis.analysis_result.get('enhanced_ai_analysis', {}).get('recommendations') else 0
            ]
            analysis.confidence_score = max(confidence_scores)
            analysis.save()
        except Exception as e:
            logger.error(f"Error updating confidence score: {str(e)}")
    
    def _create_empty_analysis(self):
        """Create empty analysis when no scan results found"""
        AIAnalysis.objects.create(
            user=self.scan.user,
            scan_id=str(self.scan.id),
            scan_identifier=self.scan.target_url,
            analysis_type='no_data',
            analysis_result={'error': 'No scan results found to analyze'},
            confidence_score=0
        )
    
    def _create_error_analysis(self, error_message):
        """Create error analysis entry"""
        try:
            AIAnalysis.objects.create(
                user=self.scan.user,
                scan_id=str(self.scan.id),
                scan_identifier=self.scan.target_url,
                analysis_type='error',
                analysis_result={
                    'error': error_message,
                    'traceback': traceback.format_exc()
                },
                confidence_score=0
            )
        except Exception as inner_e:
            logger.error(f"Failed to create error analysis record: {str(inner_e)}")
    
    def _run_threat_detection(self, scan_results, analysis):
        """Run threat detection analysis with better error handling"""
        try:
            headers_data = []
            for result in scan_results.filter(category='headers'):
                try:
                    headers_data.append(result.details)
                except Exception as e:
                    logger.warning(f"Error processing header result {result.id}: {str(e)}")
            
            if not headers_data:
                return {'threat_count': 0, 'threats': [], 'confidence': 0.5}
            
            threat_results = self._detect_threats(headers_data)
            
            # Create recommendations
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
                except Exception as e:
                    logger.error(f"Error creating recommendation: {str(e)}")
            
            threat_results['confidence'] = 0.85 if threat_results.get('threats') else 0.5
            return threat_results
                
        except Exception as e:
            logger.exception(f"Error in threat detection: {str(e)}")
            return {'threat_count': 0, 'threats': [], 'confidence': 0, 'error': str(e)}
    
    def _run_anomaly_detection(self, scan_results, analysis):
        """Run anomaly detection analysis with better error handling"""
        try:
            ssl_data = []
            for result in scan_results.filter(category='ssl'):
                try:
                    ssl_data.append(result.details)
                except Exception as e:
                    logger.warning(f"Error processing SSL result {result.id}: {str(e)}")
            
            if not ssl_data:
                return {'anomaly_count': 0, 'anomalies': [], 'confidence': 0.5}
            
            anomaly_results = self._detect_anomalies(ssl_data)
            
            # Create recommendations
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
                except Exception as e:
                    logger.error(f"Error creating recommendation: {str(e)}")
            
            anomaly_results['confidence'] = 0.85 if anomaly_results.get('anomalies') else 0.5
            return anomaly_results
                
        except Exception as e:
            logger.exception(f"Error in anomaly detection: {str(e)}")
            return {'anomaly_count': 0, 'anomalies': [], 'confidence': 0, 'error': str(e)}
    
    def _run_risk_scoring(self, scan_results, analysis):
        """Run risk scoring analysis with better error handling"""
        try:
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
                    logger.warning(f"Error processing result {result.id}: {str(e)}")
            
            risk_results = self._calculate_risk_score(all_data)
            
            # Create overall recommendation
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
            except Exception as e:
                logger.error(f"Error creating overall recommendation: {str(e)}")
            
            risk_results['confidence'] = 0.95
            return risk_results
                
        except Exception as e:
            logger.exception(f"Error in risk scoring: {str(e)}")
            return {'overall_score': 0, 'error': str(e), 'confidence': 0}
    
    def _detect_threats(self, headers_data):
        """Detect security threats in headers data"""
        threats = []
        
        for header_item in headers_data:
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
        anomalies = []
        
        for ssl_item in ssl_data:
            if 'cipher_suite' in ssl_item and 'weak' in ssl_item.get('cipher_suite', '').lower():
                anomalies.append({
                    'component': 'SSL Cipher Suites',
                    'description': 'Detected weak cipher suites in SSL/TLS configuration.',
                    'severity': 'high',
                    'recommendation': 'Disable weak cipher suites and use only strong encryption.',
                    'score': 0.92
                })
            
            if 'current_protocol' in ssl_item and ssl_item.get('current_protocol') in ['SSLv3', 'TLSv1', 'TLSv1.1']:
                anomalies.append({
                    'component': 'SSL/TLS Protocol',
                    'description': 'Detected outdated SSL/TLS protocol version.',
                    'severity': 'high',
                    'recommendation': 'Update to TLSv1.2 or TLSv1.3 and disable older protocols.',
                    'score': 0.95
                })
            
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
        category_scores = {
            'headers': 0,
            'ssl': 0,
            'vulnerabilities': 0,
            'content': 0
        }
        
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