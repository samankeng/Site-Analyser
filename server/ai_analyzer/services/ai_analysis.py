# backend/ai_analyzer/services/ai_analysis.py

import logging
import time
import traceback
import json
from typing import Dict, List, Any, Optional
from ..models import AIAnalysis, AIRecommendation
from scanner.models import ScanResult
from integrations.shodan_service import ShodanService
from ai_analyzer.services.threat_intelligence import ThreatIntelligence
from ai_analyzer.services.llm_service import LLMService
import openai
from django.conf import settings

# Set up more detailed logging
logger = logging.getLogger(__name__)

class EnhancedAIAgent:
    """
    Enhanced AI agent that provides direct, actionable vulnerability remediation advice
    """
    
    def __init__(self):
        # Initialize OpenAI client with new v1.0+ API
        self.client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
    
    def analyze_scan_results_with_ai(self, scan_results, target_url: str) -> Dict[str, Any]:
        """
        Direct AI analysis of raw scan results for actionable recommendations
        """
        try:
            # Format scan results for AI consumption
            formatted_results = self._format_scan_results_for_ai(scan_results, target_url)
            
            # Create structured prompt
            prompt = self._create_comprehensive_prompt(formatted_results)
            
            # Get AI analysis using new OpenAI API v1.0+
            ai_response = self._get_llm_response_v2(
                prompt, 
                system_prompt="You are a cybersecurity expert providing actionable vulnerability remediation advice."
            )
            
            # Parse and structure the response
            return self._parse_ai_remediation_response(ai_response)
            
        except Exception as e:
            logger.exception(f"Error in AI agent analysis: {str(e)}")
            return {
                "error": str(e),
                "recommendations": [],
                "risk_assessment": "unknown"
            }
    
    def _get_llm_response_v2(self, prompt: str, system_prompt: str = "") -> str:
        """
        Get LLM response using OpenAI API v1.0+ (replaces old LLMService)
        """
        try:
            logger.info("Requesting AI analysis from OpenAI")
            
            # Use new OpenAI API v1.0+
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",  # or "gpt-4" if you have access
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt or "You are a helpful cybersecurity expert."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3,
                response_format={"type": "json_object"}  # Ensures JSON response
            )
            
            # Extract response using new API format
            ai_response = response.choices[0].message.content
            logger.info("Successfully received AI response")
            
            return ai_response
            
        except Exception as e:
            logger.error(f"Error getting LLM response: {str(e)}")
            # Return a structured error response
            return json.dumps({
                "error": f"AI analysis failed: {str(e)}",
                "overall_risk_level": "Medium",
                "recommendations": [
                    {
                        "issue_name": "AI Analysis Unavailable",
                        "severity": "info",
                        "risk_assessment": "AI analysis could not be completed at this time",
                        "remediation_steps": ["Review scan results manually", "Run scan again later"],
                        "priority": "low"
                    }
                ]
            })
    
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
            "code_examples": {{
                "description": "What this configuration does",
                "before": "Current vulnerable configuration",
                "after": "Secure configuration example"
            }},
            "priority": "immediate|high|medium|low",
            "estimated_effort": "30 minutes|2 hours|1 day|1 week",
            "verification_steps": [
                "How to verify the fix worked"
            ]
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
            # Try to parse as JSON first
            parsed_response = json.loads(ai_response)
            
            # Validate required fields and add defaults
            if 'recommendations' not in parsed_response:
                parsed_response['recommendations'] = []
            
            if 'overall_risk_level' not in parsed_response:
                parsed_response['overall_risk_level'] = 'Medium'
            
            if 'security_score' not in parsed_response:
                parsed_response['security_score'] = 50
            
            # Ensure each recommendation has required fields
            for rec in parsed_response['recommendations']:
                rec.setdefault('severity', 'medium')
                rec.setdefault('priority', 'medium')
                rec.setdefault('estimated_effort', 'unknown')
                rec.setdefault('remediation_steps', [])
                rec.setdefault('verification_steps', [])
                rec.setdefault('business_impact', 'Security improvement recommended')
                rec.setdefault('technical_details', 'See remediation steps for details')
            
            logger.info(f"Successfully parsed AI response with {len(parsed_response['recommendations'])} recommendations")
            return parsed_response
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI JSON response: {str(e)}")
            # Fallback: create basic recommendations from text
            return self._manual_parse_response(ai_response)
    
    def _manual_parse_response(self, response: str) -> Dict[str, Any]:
        """Manually parse AI response when JSON parsing fails"""
        logger.info("Using manual parsing fallback for AI response")
        
        # Extract key information from text response
        lines = response.split('\n')
        recommendations = []
        
        # Look for bullet points or numbered items that might be recommendations
        current_rec = None
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Look for recommendation indicators
            if any(indicator in line.lower() for indicator in ['recommend', 'fix', 'implement', 'address']):
                if current_rec:
                    recommendations.append(current_rec)
                
                current_rec = {
                    "issue_name": line[:50] + "..." if len(line) > 50 else line,
                    "severity": "medium",
                    "risk_assessment": line,
                    "remediation_steps": [line],
                    "priority": "medium",
                    "estimated_effort": "unknown"
                }
            elif current_rec and line:
                # Add additional context to current recommendation
                current_rec["risk_assessment"] += " " + line
        
        # Add the last recommendation
        if current_rec:
            recommendations.append(current_rec)
        
        # If no recommendations found, create a basic one
        if not recommendations:
            recommendations.append({
                "issue_name": "Manual Review Required",
                "severity": "medium",
                "risk_assessment": "AI analysis completed but requires manual review of results",
                "remediation_steps": [
                    "Review scan findings manually",
                    "Prioritize critical and high severity issues",
                    "Implement security best practices"
                ],
                "priority": "medium",
                "estimated_effort": "varies"
            })
        
        return {
            "overall_risk_level": "Medium",
            "security_score": 50,
            "recommendations": recommendations,
            "executive_summary": "AI analysis completed with manual parsing",
            "quick_wins": ["Review and prioritize security findings"],
            "long_term_strategy": "Implement comprehensive security monitoring",
            "fallback_used": True,
            "raw_response": response[:500] + "..." if len(response) > 500 else response
        }

class AIAnalysisService:
    """Service for performing AI-based security analysis with improved error handling"""
    
    def __init__(self, scan):
        self.scan = scan
        self.start_time = time.time()
        
        # Initialize external services
        self.threat_intel = ThreatIntelligence()
        self.shodan = ShodanService()
        
        # Initialize enhanced AI agent
        self.enhanced_agent = EnhancedAIAgent()
    
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
            
            # Create a single analysis record for this scan
            analysis = AIAnalysis.objects.create(
                user=self.scan.user,
                scan_id=str(self.scan.id),
                scan_identifier=self.scan.target_url,
                analysis_type='combined',
                analysis_result={
                    'threat_detection': {},
                    'anomaly_detection': {},
                    'risk_scoring': {},
                    'enhanced_ai_analysis': {},  # New field for enhanced AI analysis
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
            
            # NEW: Run enhanced AI analysis for direct actionable recommendations
            logger.info("Starting enhanced AI analysis")
            try:
                enhanced_ai_results = self._run_enhanced_ai_analysis(scan_results, analysis)
                logger.info("Enhanced AI analysis completed successfully")
                
                # Update analysis with enhanced AI results
                analysis.analysis_result['enhanced_ai_analysis'] = enhanced_ai_results
                analysis.save()
            except Exception as e:
                logger.error(f"Error in enhanced AI analysis: {str(e)}")
                logger.error(traceback.format_exc())
            
            # Update confidence score based on all analyses
            try:
                # Assign the highest confidence score from all analyses
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
    
    def _run_enhanced_ai_analysis(self, scan_results, analysis):
        """
        NEW METHOD: Enhanced AI analysis that provides direct actionable recommendations
        """
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
                        # Prepare metadata
                        metadata = {
                            'business_impact': rec.get('business_impact', ''),
                            'technical_details': rec.get('technical_details', ''),
                            'code_examples': rec.get('code_examples', {}),
                            'verification_steps': rec.get('verification_steps', []),
                            'implementation_complexity': self._assess_implementation_complexity(rec),
                            'estimated_time': self._estimate_implementation_time(rec)
                        }
                        
                        # Create recommendation record
                        AIRecommendation.objects.create(
                            analysis=analysis,
                            title=rec.get('issue_name', 'AI Generated Recommendation'),
                            description=rec.get('risk_assessment', rec.get('description', '')),
                            severity=rec.get('severity', 'medium'),
                            recommendation=json.dumps(rec.get('remediation_steps', [])),
                            recommendation_type='ai_enhanced',
                            confidence_score=0.9,
                            metadata=metadata
                        )
                        recs_created += 1
                    except Exception as e:
                        logger.error(f"Error creating AI recommendation: {str(e)}")
                
                logger.info(f"Created {recs_created} enhanced AI recommendations")
            
            # Add metadata about the scan
            ai_recommendations["metadata"] = {
                "total_scan_results": scan_results.count(),
                "categories_scanned": list(scan_results.values_list('category', flat=True).distinct()),
                "severity_distribution": {
                    severity: scan_results.filter(severity=severity).count()
                    for severity in ['critical', 'high', 'medium', 'low', 'info']
                }
            }
            
            return ai_recommendations
            
        except Exception as e:
            logger.exception(f"Error in enhanced AI analysis: {str(e)}")
            return {"error": str(e), "recommendations": []}
    
    def _assess_implementation_complexity(self, recommendation: Dict[str, Any]) -> str:
        """Assess how complex a recommendation is to implement"""
        category = recommendation.get('category', '').lower()
        
        complexity_map = {
            'headers': 'Low',     # Usually just server config
            'ssl': 'Medium',      # May require certificate renewal
            'content': 'High',    # May require code changes
            'configuration': 'Low' # Usually config changes
        }
        
        return complexity_map.get(category, 'Medium')
    
    def _estimate_implementation_time(self, recommendation: Dict[str, Any]) -> str:
        """Estimate time needed to implement a recommendation"""
        complexity = self._assess_implementation_complexity(recommendation)
        severity = recommendation.get('severity', 'medium').lower()
        
        time_estimates = {
            ('Low', 'critical'): '1-2 hours',
            ('Low', 'high'): '2-4 hours',
            ('Low', 'medium'): '1-3 hours',
            ('Low', 'low'): '30 minutes - 1 hour',
            ('Medium', 'critical'): '4-8 hours',
            ('Medium', 'high'): '2-6 hours',
            ('Medium', 'medium'): '1-4 hours',
            ('Medium', 'low'): '1-2 hours',
            ('High', 'critical'): '1-2 days',
            ('High', 'high'): '4-8 hours',
            ('High', 'medium'): '2-6 hours',
            ('High', 'low'): '2-4 hours'
        }
        
        return time_estimates.get((complexity, severity), '2-4 hours')
    
    # ... [Rest of your existing methods remain the same] ...
    
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