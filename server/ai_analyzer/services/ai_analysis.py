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
from django.utils import timezone
from .specific_recommendations import SpecificRecommendationGenerator

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
    
    def analyze_scan_results_with_ai(self, scan_results, target_url: str, scanner_score: int = None) -> Dict[str, Any]:
        """
        Direct AI analysis of raw scan results for actionable recommendations
        
        Args:
            scan_results: The scan results to analyze
            target_url: The target URL that was scanned
            scanner_score: The security score calculated by the scanner (0-100)
        """
        try:
            if not self.client:
                logger.warning("OpenAI client not available, returning fallback response")
                return self._create_fallback_response(scan_results, target_url, scanner_score)
            
            # Format scan results for AI consumption
            formatted_results = self._format_scan_results_for_ai(scan_results, target_url)
            
            # Create structured prompt WITH THE SCANNER SCORE
            prompt = self._create_comprehensive_prompt(formatted_results, scanner_score)
            
            # Get AI analysis using OpenAI API v1.0+
            ai_response = self._get_llm_response(prompt)
            
            # Parse and structure the response
            return self._parse_ai_remediation_response(ai_response, scanner_score)
            
        except Exception as e:
            logger.exception(f"Error in AI agent analysis: {str(e)}")
            return self._create_fallback_response(scan_results, target_url, scanner_score)
    
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
    
    def _create_fallback_response(self, scan_results, target_url: str, scanner_score: int = None) -> Dict[str, Any]:
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
        
        # Use the scanner score if provided, otherwise calculate a basic one
        if scanner_score is None:
            scanner_score = max(20, 100 - (severity_counts["critical"] * 15 + severity_counts["high"] * 8))
        
        # Calculate basic risk level based on scanner score
        if scanner_score < 50:
            risk_level = "Critical"
        elif scanner_score < 70:
            risk_level = "High"  
        elif scanner_score < 85:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        return {
            "overall_risk_level": risk_level,
            "security_score": scanner_score,  # Use the scanner's score
            "executive_summary": f"Security analysis completed for {target_url}. Security score: {scanner_score}/100. Found {sum(severity_counts.values())} total issues.",
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
            "scan_timestamp": scan_results[0].created_at.isoformat() if scan_results else None,
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
    
    def _create_comprehensive_prompt(self, formatted_results: Dict[str, Any], scanner_score: int = None) -> str:
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
        
        # Include the scanner score in the prompt
        scanner_score_text = f"\nSCANNER SECURITY SCORE: {scanner_score}/100" if scanner_score is not None else ""
        
        prompt = f"""
    You are a cybersecurity expert analyzing web security scan results. Provide detailed, actionable remediation advice in JSON format.

    TARGET: {formatted_results['target_url']}
    SCAN DATE: {formatted_results.get('scan_timestamp', 'Unknown')}
    TOTAL FINDINGS: {total_findings}{scanner_score_text}

    IMPORTANT: The scanner has calculated a security score of {scanner_score}/100. Use this as your baseline security_score in your response.

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
        "security_score": {scanner_score if scanner_score is not None else '0-100 (use the scanner score provided above)'},
        "executive_summary": "Brief summary for stakeholders that references the security score of {scanner_score}/100",
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
    
    def _parse_ai_remediation_response(self, ai_response: str, scanner_score: int = None) -> Dict[str, Any]:
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
            
            # IMPORTANT: Use the scanner score if provided
            if scanner_score is not None:
                parsed_response['security_score'] = scanner_score
            else:
                parsed_response.setdefault('security_score', 50)
            
            parsed_response.setdefault('executive_summary', f'Security analysis completed. Security score: {parsed_response["security_score"]}/100')
            
            # Ensure each recommendation has required fields
            for rec in parsed_response['recommendations']:
                rec.setdefault('severity', 'medium')
                rec.setdefault('priority', 'medium')
                rec.setdefault('estimated_effort', 'unknown')
                rec.setdefault('remediation_steps', [])
                rec.setdefault('business_impact', 'Security improvement recommended')
                rec.setdefault('technical_details', 'See remediation steps for details')
            
            logger.info(f"Successfully parsed AI response with {len(parsed_response['recommendations'])} recommendations and score {parsed_response['security_score']}/100")
            return parsed_response
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI JSON response: {str(e)}")
            # Return manual parsing fallback
            return self._manual_parse_response(ai_response, scanner_score)
    
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
        self.security_score = None  # Store score at class level
        self.risk_results = None    # Store full risk results
        
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
        self.recommendation_generator = SpecificRecommendationGenerator()
    
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
            
            # CALCULATE SECURITY SCORE ONCE AT THE BEGINNING
            self._calculate_security_score_once(scan_results)
            
            # Create analysis record with the calculated score
            analysis = AIAnalysis.objects.create(
                user=self.scan.user,
                scan_id=str(self.scan.id),
                scan_identifier=self.scan.target_url,
                analysis_type='combined',
                analysis_result={
                    'enhanced_ai_analysis': {},
                    'threat_detection': {},
                    'anomaly_detection': {},
                    'risk_scoring': {},
                    'security_score': self.security_score  # Store the score here
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
    
    def _calculate_security_score_once(self, scan_results):
        """Calculate security score once at the beginning of analysis"""
        try:
            from ai_analyzer.ml.risk_scoring.model import RiskScoringModel
            risk_model = RiskScoringModel()
            
            # Prepare scan data for scoring
            scan_data = {}
            for result in scan_results:
                category = result.category
                if category not in scan_data:
                    scan_data[category] = []
                scan_data[category].append({
                    'name': result.name,
                    'severity': result.severity,
                    'details': result.details
                })
            
            # Calculate the risk score ONCE
            self.risk_results = risk_model.calculate_risk_score(scan_data)
            self.security_score = self.risk_results['overall_score']
            
            logger.info(f"Security score calculated once: {self.security_score}/100")
            logger.info(f"Risk results: {json.dumps(self.risk_results, indent=2)}")
            
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            self.security_score = 50  # Default fallback
            self.risk_results = {
                'overall_score': 50,
                'error': str(e),
                'improvement_suggestions': 'Unable to calculate detailed suggestions due to error',
                'category_scores': {},
                'severity_counts': {}
            }
    
    def _run_enhanced_ai_analysis(self, scan_results, analysis):
        """Enhanced AI analysis with OpenAI-powered specific recommendations"""
        try:
            logger.info("🤖 === STARTING ENHANCED AI ANALYSIS ===")
            logger.info(f"Input scan_results type: {type(scan_results)}")
            logger.info(f"Input scan_results count: {scan_results.count() if hasattr(scan_results, 'count') else len(scan_results)}")
            
            # Convert to list and log sample
            scan_results_list = list(scan_results)
            logger.info(f"📊 Processing {len(scan_results_list)} scan results for AI analysis")
            
            # Log first 3 results for debugging
            for i, result in enumerate(scan_results_list[:3]):
                logger.info(f"  Result {i+1}:")
                logger.info(f"    ID: {result.id}")
                logger.info(f"    Category: {result.category}")
                logger.info(f"    Name: {result.name}")
                logger.info(f"    Severity: {result.severity}")
                logger.info(f"    Description: {result.description[:100]}...")
                if hasattr(result, 'details'):
                    logger.info(f"    Details keys: {list(result.details.keys()) if result.details else 'None'}")

            # Use the pre-calculated security score
            scanner_score = self.security_score
            logger.info(f"🎯 Using pre-calculated security score: {scanner_score}/100")
            
            # LOG TARGET INFO
            logger.info(f"🌐 Target URL: {self.scan.target_url}")
            logger.info(f"🆔 Scan ID: {self.scan.id}")
            
            # === PHASE 1: OPENAI SPECIFIC RECOMMENDATIONS ===
            logger.info("🎯 === PHASE 1: GENERATING OPENAI SPECIFIC RECOMMENDATIONS ===")
            
            openai_recommendations = []
            openai_success = False
            
            try:
                # Generate OpenAI-powered specific recommendations
                if hasattr(self, 'specific_rec_generator'):
                    logger.info("🤖 Generating OpenAI-powered specific recommendations...")
                    
                    openai_recs = self.specific_rec_generator.generate_recommendations_for_scan(
                        scan_results_list, self.scan.target_url
                    )
                    
                    logger.info(f"✅ Generated {len(openai_recs)} OpenAI specific recommendations")
                    
                    # Save OpenAI recommendations to database
                    openai_saved_count = 0
                    for rec_data in openai_recs:
                        try:
                            # Format the recommendation for display
                            formatted_description = self.specific_rec_generator.format_recommendation_for_display(rec_data)
                            
                            # Create the recommendation record
                            openai_recommendation = AIRecommendation.objects.create(
                                analysis=analysis,
                                title=rec_data['title'],
                                description=formatted_description,
                                severity=rec_data.get('severity', 'medium'),
                                confidence_score=rec_data.get('confidence', 90) / 100,
                                recommendation_type='openai_specific',
                                metadata={
                                    'openai_data': rec_data,
                                    'category': rec_data.get('category'),
                                    'issues_count': rec_data.get('issues_count'),
                                    'estimated_fix_time': rec_data.get('estimated_fix_time'),
                                    'priority': rec_data.get('priority'),
                                    'security_score': scanner_score,
                                    'model_used': rec_data.get('model_used', 'gpt-4o')
                                }
                            )
                            
                            openai_recommendations.append(openai_recommendation)
                            openai_saved_count += 1
                            logger.info(f"💾 Saved OpenAI recommendation: {openai_recommendation.title}")
                            
                        except Exception as e:
                            logger.error(f"❌ Error saving OpenAI recommendation: {str(e)}")
                            continue
                    
                    logger.info(f"✅ Saved {openai_saved_count} OpenAI specific recommendations")
                    openai_success = True
                    
                else:
                    logger.warning("⚠️ OpenAI specific recommendation generator not available")
                    
            except Exception as e:
                logger.error(f"❌ Error in OpenAI specific recommendations: {str(e)}")
                logger.error(f"🔍 Traceback: {traceback.format_exc()}")
            
            # === PHASE 2: ENHANCED AI AGENT ANALYSIS ===
            logger.info("🧠 === PHASE 2: ENHANCED AI AGENT ANALYSIS ===")
            
            ai_recommendations = {}
            enhanced_ai_success = False
            
            try:
                # Get AI-powered recommendations from enhanced agent
                logger.info("🤖 Calling enhanced AI agent...")
                
                if hasattr(self, 'enhanced_agent'):
                    ai_recommendations = self.enhanced_agent.analyze_scan_results_with_ai(
                        scan_results_list, 
                        self.scan.target_url,
                        scanner_score  # Pass the pre-calculated score
                    )
                    
                    # LOG AI AGENT RESPONSE
                    logger.info("=== AI AGENT RESPONSE ===")
                    logger.info(f"AI recommendations keys: {ai_recommendations.keys()}")
                    logger.info(f"Security score from AI: {ai_recommendations.get('security_score', 'NOT SET')}")
                    logger.info(f"Risk level: {ai_recommendations.get('overall_risk_level', 'NOT SET')}")
                    logger.info(f"Number of recommendations: {len(ai_recommendations.get('recommendations', []))}")
                    
                    # Log first recommendation sample
                    if ai_recommendations.get('recommendations'):
                        first_rec = ai_recommendations['recommendations'][0]
                        logger.info(f"Sample AI agent recommendation:")
                        logger.info(f"  Issue: {first_rec.get('issue_name', 'N/A')}")
                        logger.info(f"  Severity: {first_rec.get('severity', 'N/A')}")
                        logger.info(f"  Steps: {len(first_rec.get('remediation_steps', []))} steps")
                    
                    # Ensure the AI uses the scanner score
                    ai_recommendations['security_score'] = scanner_score
                    
                    # Store enhanced AI agent recommendations in database
                    if 'recommendations' in ai_recommendations:
                        ai_recs_created = 0
                        for rec in ai_recommendations['recommendations']:
                            try:
                                # Create recommendation record
                                AIRecommendation.objects.create(
                                    analysis=analysis,
                                    title=rec.get('issue_name', 'AI Enhanced Recommendation'),
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
                                        'category': rec.get('category', 'general'),
                                        'security_score': scanner_score,
                                        'ai_agent_analysis': True
                                    }
                                )
                                ai_recs_created += 1
                            except Exception as e:
                                logger.error(f"❌ Error creating AI agent recommendation: {str(e)}")
                        
                        logger.info(f"✅ Created {ai_recs_created} enhanced AI agent recommendations")
                        enhanced_ai_success = True
                    
                else:
                    logger.warning("⚠️ Enhanced AI agent not available")
                    
            except Exception as e:
                logger.error(f"❌ Error in enhanced AI agent analysis: {str(e)}")
                logger.error(f"🔍 Traceback: {traceback.format_exc()}")
            
            # === PHASE 3: COMBINE AND SUMMARIZE RESULTS ===
            logger.info("📊 === PHASE 3: COMBINING RESULTS ===")
            
            # Count total recommendations created
            total_openai_recs = len(openai_recommendations)
            total_ai_agent_recs = len(ai_recommendations.get('recommendations', []))
            total_recommendations = total_openai_recs + total_ai_agent_recs
            
            logger.info(f"📈 ANALYSIS SUMMARY:")
            logger.info(f"  OpenAI Specific Recommendations: {total_openai_recs}")
            logger.info(f"  AI Agent Recommendations: {total_ai_agent_recs}")
            logger.info(f"  Total Recommendations: {total_recommendations}")
            logger.info(f"  Security Score: {scanner_score}/100")
            
            # Create comprehensive result
            enhanced_analysis_result = {
                'status': 'success',
                'security_score': scanner_score,
                'overall_risk_level': ai_recommendations.get('overall_risk_level', 'medium'),
                
                # OpenAI Specific Recommendations
                'openai_recommendations': {
                    'success': openai_success,
                    'count': total_openai_recs,
                    'method': 'openai_gpt4_specific'
                },
                
                # Enhanced AI Agent
                'enhanced_ai_agent': {
                    'success': enhanced_ai_success,
                    'count': total_ai_agent_recs,
                    'method': 'enhanced_ai_agent'
                },
                
                # Combined results
                'total_recommendations': total_recommendations,
                'recommendations_breakdown': {
                    'openai_specific': total_openai_recs,
                    'ai_enhanced': total_ai_agent_recs
                },
                
                # Analysis metadata
                'scan_results_analyzed': len(scan_results_list),
                'target_url': self.scan.target_url,
                'analysis_timestamp': timezone.now().isoformat()
            }
            
            # Include original AI recommendations for compatibility
            if ai_recommendations:
                enhanced_analysis_result.update(ai_recommendations)
            
            logger.info("🎉 === ENHANCED AI ANALYSIS COMPLETED SUCCESSFULLY ===")
            logger.info(f"✅ Total processing time: {time.time() - self.start_time:.2f} seconds")
            
            return enhanced_analysis_result
            
        except Exception as e:
            logger.exception(f"💥 CRITICAL ERROR in enhanced AI analysis: {str(e)}")
            logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
            
            return {
                "status": "error",
                "error": str(e), 
                "recommendations": [], 
                "security_score": self.security_score,
                "openai_recommendations": {"success": False, "count": 0},
                "enhanced_ai_agent": {"success": False, "count": 0},
                "total_recommendations": 0
            }
    
    
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
        """Run enhanced anomaly detection with proper data formatting"""
        try:
            logger.info("Starting enhanced anomaly detection analysis")
            
            # Convert Django QuerySet to the format your anomaly detector expects
            scan_results_list = []
            logger.info(f"Processing {scan_results.count()} scan results for anomaly detection")

            for result in scan_results:
                # Format each ScanResult as a dictionary that your anomaly detector can understand
                formatted_result = {
                    'id': result.id,
                    'category': result.category,
                    'name': result.name,
                    'description': result.description,
                    'severity': result.severity,
                    'details': result.details if hasattr(result, 'details') else {},
                    'created_at': result.created_at.isoformat() if hasattr(result, 'created_at') else None,
                    'scan_id': str(self.scan.id),
                    'target_url': self.scan.target_url
                }
                scan_results_list.append(formatted_result)
                
            
            logger.info(f"Formatted {len(scan_results_list)} scan results for anomaly detection")
            
            # Debug: Log first few results to see the format
            if scan_results_list:
                logger.info(f"Sample formatted result: {scan_results_list[0]}")
                
            # Now call your enhanced connection anomaly detection
            # This should match the format your frontend anomalyService.detectConnectionAnomalies expects
            try:
                # Import your enhanced detection (might be in a different location)
                from ai_analyzer.ml.anomaly_detection.model import AnomalyDetectionModel
                anomaly_detector = AnomalyDetectionModel()
                
                # Use the properly formatted data
                logger.info("Calling AnomalyDetectionModel.detect_anomalies()...")
                anomaly_results = anomaly_detector.detect_anomalies(scan_results_list)
                
            except ImportError:
                # If the ML model isn't available, use your enhanced logic directly
                logger.warning("ML anomaly model not available, using direct enhanced detection")
                anomaly_results = self._run_enhanced_connection_anomaly_detection(scan_results_list)
            
            logger.info("=== ANOMALY DETECTION RESULTS ===")
            logger.info(f"Anomaly results keys: {anomaly_results.keys()}")
            logger.info(f"Is anomaly: {anomaly_results.get('is_anomaly', False)}")
            logger.info(f"Anomaly score: {anomaly_results.get('anomaly_score', 0.0)}")
            logger.info(f"Number of anomalies: {len(anomaly_results.get('anomalies', []))}")
            
            # FIXED: Create recommendations from enhanced anomaly detection with proper component names
            if anomaly_results.get('anomalies'):
                for anomaly in anomaly_results['anomalies']:
                    try:
                        # FIXED: Get proper component name from anomaly type
                        component_name = self._get_component_name_from_type(
                            anomaly.get('type', anomaly.get('component', 'unknown'))
                        )
                        
                        # CREATE AIRecommendation record (existing logic)
                        AIRecommendation.objects.create(
                            analysis=analysis,
                            title=f"Enhanced Anomaly: {component_name}",  # FIXED: Use mapped component name
                            description=anomaly.get('description', 'Anomaly detected'),
                            severity=anomaly.get('severity', 'medium'),
                            recommendation=anomaly.get('recommendation', 'Review and address this anomaly'),
                            recommendation_type='anomaly_detection',
                            confidence_score=anomaly.get('score', 0.5),
                            metadata={
                                'anomaly_id': anomaly.get('id', ''),
                                'component': component_name,  # FIXED: Store mapped component name
                                'original_type': anomaly.get('type', ''),  # Keep original type for debugging
                                'details': anomaly.get('details', {}),
                                'is_false_positive': anomaly.get('is_false_positive', False),
                                'detection_method': 'enhanced_connection_detection'
                            }
                        )
                        logger.info(f"Created enhanced anomaly recommendation: {component_name}")
                        
                        # NEW: ALSO CREATE Anomaly model record in ai_analyzer_anomaly table
                        from ..models import Anomaly
                        Anomaly.objects.create(
                            scan_id=str(self.scan.id),  # FIXED: scan_id field (not scan)
                            component=component_name,
                            severity=anomaly.get('severity', 'medium'),
                            description=anomaly.get('description', 'Anomaly detected'),
                            details=anomaly.get('details', {}),
                            score=anomaly.get('score', 0.5),
                            is_false_positive=False,
                            recommendation=anomaly.get('recommendation', 'Review and address this anomaly')
                            # REMOVED: anomaly_type field (doesn't exist in your table)
                        )
                        logger.info(f"Created Anomaly model record: {component_name}")
                        
                    except Exception as e:
                        logger.error(f"Error creating anomaly records: {str(e)}")
            
            # Return enhanced results
            enhanced_results = {
                'anomaly_count': len(anomaly_results.get('anomalies', [])),
                'anomalies': anomaly_results.get('anomalies', []),
                'is_anomaly': anomaly_results.get('is_anomaly', False),
                'anomaly_score': anomaly_results.get('anomaly_score', 0.0),
                'model_based': anomaly_results.get('model_based', False),
                'confidence': 0.9 if anomaly_results.get('anomalies') else 0.5,
                'detection_method': 'enhanced_connection_anomaly_detection'
            }
            
            logger.info(f"Enhanced anomaly detection found {enhanced_results['anomaly_count']} anomalies with score {enhanced_results['anomaly_score']}")
            
            return enhanced_results
            
        except Exception as e:
            logger.exception(f"Error in enhanced anomaly detection: {str(e)}")
            return {
                'anomaly_count': 0, 
                'anomalies': [], 
                'confidence': 0, 
                'error': str(e),
                'detection_method': 'error_fallback'
            }

    def _get_component_name_from_type(self, anomaly_type):
        """Convert anomaly type to user-friendly component name - ADD THIS METHOD"""
        type_to_component_map = {
            'missing_security_headers': 'Security Headers',
            'critical_security_headers_missing': 'Critical Security Headers',
            'ssl_configuration_issues': 'SSL/TLS Configuration',
            'medium_severity_concentration': 'Issue Concentration Analysis',
            'high_severity_concentration': 'High Severity Issues',
            'excessive_issue_count': 'Issue Volume Analysis',
            'vulnerability_cluster': 'Vulnerability Clustering',
            'critical_vulnerability_cluster': 'Critical Vulnerabilities',
            'performance_degradation': 'Performance Analysis',
            'connection_timeouts': 'Connection Issues',
            'ssl_test_site_patterns': 'SSL Test Site Detection',
            'content_security_issues': 'Content Security',
            'scan_failure_anomalies': 'Scan Quality',
            'unknown': 'General Analysis'
        }
        
        return type_to_component_map.get(anomaly_type, 'General Analysis')

    def _run_enhanced_connection_anomaly_detection(self, scan_results_list):
        """
        Enhanced connection anomaly detection logic 
        (ported from your frontend anomalyService.detectConnectionAnomalies)
        """
        anomalies = []
        
        logger.info(f"Analyzing {len(scan_results_list)} scan results for connection anomalies...")
        
        # SSL certificate issues
        ssl_errors = [r for r in scan_results_list if 
                    'certificate' in r.get('description', '').lower() or
                    'SSL: CERTIFICATE_VERIFY_FAILED' in r.get('description', '') or
                    'ssl' in r.get('name', '').lower() and 'expired' in r.get('description', '')]
        
        if ssl_errors:
            logger.info(f"Found {len(ssl_errors)} SSL certificate errors")
            anomalies.append({
                'id': f'ssl-expired-{int(time.time())}',
                'component': 'SSL Certificate',
                'description': f'SSL certificate issues detected, causing {len(ssl_errors)} connection failures',
                'severity': 'high',
                'recommendation': 'Renew the SSL certificate immediately to restore secure HTTPS connections',
                'score': 1.0,
                'is_false_positive': False,
                'created_at': timezone.now().isoformat(),
                'details': {
                    'affected_scans': [e.get('category') for e in ssl_errors],
                    'error_count': len(ssl_errors)
                }
            })
        
        # Timeout issues
        timeouts = [r for r in scan_results_list if 
                    'timeout' in r.get('description', '').lower() or
                    'SoftTimeLimitExceeded' in r.get('description', '')]
        
        if timeouts:
            logger.info(f"Found {len(timeouts)} timeout errors")
            anomalies.append({
                'id': f'timeout-{int(time.time())}',
                'component': 'Performance',
                'description': f'Scan timeouts detected ({len(timeouts)} operations timed out)',
                'severity': 'medium',
                'recommendation': 'Investigate server performance issues and optimize response times',
                'score': 0.7,
                'is_false_positive': False,
                'created_at': timezone.now().isoformat(),
                'details': {'timeout_count': len(timeouts)}
            })
        
        # Connection failures
        connection_failures = [r for r in scan_results_list if 
                            'Failed to connect' in r.get('description', '') or
                            'Connection refused' in r.get('description', '') or
                            'Connection error' in r.get('description', '')]
        
        if len(connection_failures) > 3:
            logger.info(f"Found {len(connection_failures)} connection failures")
            anomalies.append({
                'id': f'connection-failures-{int(time.time())}',
                'component': 'Website Availability',
                'description': f'Multiple connection failures detected ({len(connection_failures)} failed attempts)',
                'severity': 'high',
                'recommendation': 'Check server availability, DNS resolution, and network connectivity',
                'score': 0.9,
                'is_false_positive': False,
                'created_at': timezone.now().isoformat(),
                'details': {'failure_count': len(connection_failures)}
            })
        
        # Security header clustering (many missing headers)
        header_results = [r for r in scan_results_list if r.get('category') == 'headers']
        critical_header_issues = [h for h in header_results if h.get('severity') in ['high', 'critical']]
        
        if len(critical_header_issues) > 5:
            anomalies.append({
                'id': f'security-header-cluster-{int(time.time())}',
                'component': 'Security Headers',
                'description': f'Multiple critical security headers missing ({len(critical_header_issues)} issues)',
                'severity': 'high',
                'recommendation': 'Implement comprehensive security header policy',
                'score': 0.85,
                'is_false_positive': False,
                'created_at': timezone.now().isoformat(),
                'details': {'issue_count': len(critical_header_issues)}
            })
        
        # Check for overall high issue count (like your security score of 26/100)
        total_scans = len(scan_results_list)
        high_severity_issues = [r for r in scan_results_list if r.get('severity') in ['high', 'critical']]
        
        if len(high_severity_issues) > total_scans * 0.3:  # More than 30% high severity
            anomalies.append({
                'id': f'high-severity-cluster-{int(time.time())}',
                'component': 'Overall Security',
                'description': f'High concentration of severe security issues ({len(high_severity_issues)}/{total_scans})',
                'severity': 'critical',
                'recommendation': 'Immediate security review and remediation required',
                'score': 1.0,
                'is_false_positive': False,
                'created_at': timezone.now().isoformat(),
                'details': {
                    'high_severity_count': len(high_severity_issues),
                    'total_issues': total_scans,
                    'severity_percentage': round((len(high_severity_issues) / total_scans) * 100)
                }
            })
        
        logger.info(f"Enhanced connection anomaly detection found {len(anomalies)} anomalies")
        
        return {
            'is_anomaly': len(anomalies) > 0,
            'anomaly_score': min(1.0, len(anomalies) * 0.3),
            'anomalies': anomalies,
            'model_based': False
        }

    def _run_fallback_ssl_anomaly_detection(self, scan_results, analysis):
        """Fallback to original SSL-only anomaly detection if enhanced version fails"""
        logger.warning("Using fallback SSL-only anomaly detection")
        
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
                        title=f"SSL Anomaly: {anomaly['component']}",
                        description=anomaly['description'],
                        severity=anomaly['severity'],
                        recommendation=anomaly['recommendation'],
                        recommendation_type='ssl_anomaly',
                        confidence_score=anomaly['score']
                    )
                except Exception as e:
                    logger.error(f"Error creating SSL anomaly recommendation: {str(e)}")
            
            anomaly_results['confidence'] = 0.85 if anomaly_results.get('anomalies') else 0.5
            anomaly_results['detection_method'] = 'fallback_ssl_only'
            return anomaly_results
                
        except Exception as e:
            logger.exception(f"Error in fallback SSL anomaly detection: {str(e)}")
            return {'anomaly_count': 0, 'anomalies': [], 'confidence': 0, 'error': str(e)}
    
    def _run_risk_scoring(self, scan_results, analysis):
        """Run risk scoring analysis using pre-calculated results"""
        try:
            # Use the pre-calculated risk results and score
            risk_results = self.risk_results if self.risk_results else {'overall_score': 50}
            overall_score = self.security_score if self.security_score is not None else 50
            
            logger.info(f"Using pre-calculated score for risk scoring: {overall_score}/100")
            
            # Create overall recommendation with the SAME score
            try:
                AIRecommendation.objects.create(
                    analysis=analysis,
                    title=f"Overall Security Assessment",
                    description=f"Based on our security scan, {self.scan.target_url} has a security score of {overall_score}/100",
                    severity=self._get_severity_from_score(overall_score),
                    recommendation=risk_results.get('improvement_suggestions', 'Continue monitoring your site security regularly'),
                    recommendation_type='summary',
                    confidence_score=0.95,
                    metadata={
                        'security_score': overall_score,
                        'category_scores': risk_results.get('category_scores', {}),
                        'severity_counts': risk_results.get('severity_counts', {}),
                        'overall_severity': risk_results.get('overall_severity', 'medium')
                    }
                )
                logger.info(f"Created Overall Security Assessment with score {overall_score}/100")
            except Exception as e:
                logger.error(f"Error creating overall recommendation: {str(e)}")
            
            # Return the pre-calculated results
            return risk_results
                
        except Exception as e:
            logger.exception(f"Error in risk scoring: {str(e)}")
            return {
                'overall_score': self.security_score or 0,
                'error': str(e),
                'confidence': 0,
                'category_scores': self.risk_results.get('category_scores', {}) if self.risk_results else {},
                'severity_counts': self.risk_results.get('severity_counts', {}) if self.risk_results else {}
            }
    
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