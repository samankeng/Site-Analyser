# backend/ai_analyzer/services/llm_service.py
# UPDATED VERSION - Replace your llm_service.py with this

import logging
import json
import requests
import os
import openai
from django.conf import settings
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class LLMService:
    """Service for interacting with Large Language Models for security analysis"""
    
    def __init__(self):
        """Initialize LLM service with configured provider"""
        self.provider = getattr(settings, 'LLM_PROVIDER', 'openai')
        logger.info(f"Initializing LLM service with provider: {self.provider}")
        
        if self.provider == 'openai':
            self.api_key = getattr(settings, 'OPENAI_API_KEY', '')
            self.model = getattr(settings, 'OPENAI_MODEL_NAME', 'gpt-3.5-turbo')  # Updated default
            if not self.api_key:
                logger.error("OpenAI API key not configured")
                raise ValueError("OpenAI API key not configured")
            
            # Initialize OpenAI client with new v1.0+ API
            try:
                self.openai_client = openai.OpenAI(api_key=self.api_key)
                logger.info("OpenAI client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {str(e)}")
                self.openai_client = None
                
        elif self.provider == 'ollama':
            self.base_url = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
            self.model = getattr(settings, 'OLLAMA_MODEL_NAME', 'llama3')
        else:
            logger.error(f"Unsupported LLM provider: {self.provider}")
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
    
    def analyze_vulnerabilities(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan data to identify security vulnerabilities using LLM
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            Dictionary containing analysis results
        """
        prompt = self._create_vulnerability_analysis_prompt(scan_data)
        
        try:
            response = self._get_llm_response(prompt, system_prompt="You are a cybersecurity expert analyzing website vulnerabilities.")
            
            # Parse the response to extract structured information
            return self._parse_vulnerability_analysis(response)
        except Exception as e:
            logger.exception(f"Error analyzing vulnerabilities with LLM: {str(e)}")
            return {
                "error": str(e),
                "vulnerabilities": [],
                "risk_level": "unknown"
            }
    
    def generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate specific security recommendations based on discovered vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of recommendation dictionaries
        """
        if not vulnerabilities:
            logger.info("No vulnerabilities provided for recommendation generation")
            return []
        
        prompt = self._create_recommendations_prompt(vulnerabilities)
        
        try:
            response = self._get_llm_response(prompt, system_prompt="You are a cybersecurity expert providing actionable security recommendations.")
            
            # Parse the response to extract structured recommendations
            return self._parse_recommendations(response)
        except Exception as e:
            logger.exception(f"Error generating recommendations with LLM: {str(e)}")
            return [{
                "title": "Error generating recommendations",
                "description": f"An error occurred: {str(e)}",
                "severity": "medium",
                "recommendation": "Please try running the analysis again.",
                "confidence_score": 0.5
            }]
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate an executive summary of scan findings
        
        Args:
            scan_results: Complete scan results with analysis
            
        Returns:
            Executive summary text
        """
        prompt = self._create_executive_summary_prompt(scan_results)
        
        try:
            response = self._get_llm_response(prompt, system_prompt="You are a cybersecurity expert providing an executive summary of security scan findings.")
            
            # For executive summary, we can just return the raw text
            return response.strip()
        except Exception as e:
            logger.exception(f"Error generating executive summary with LLM: {str(e)}")
            return f"Error generating executive summary: {str(e)}"
    
    def _get_llm_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Get response from the configured LLM provider
        
        Args:
            prompt: The prompt to send to the LLM
            system_prompt: Optional system prompt for context
            
        Returns:
            Text response from the LLM
        """
        if self.provider == 'openai':
            return self._get_openai_response(prompt, system_prompt)
        elif self.provider == 'ollama':
            return self._get_ollama_response(prompt, system_prompt)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
    
    def _get_openai_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Get response from OpenAI API using v1.0+ format"""
        try:
            if not self.openai_client:
                raise Exception("OpenAI client not initialized")
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            
            messages.append({"role": "user", "content": prompt})
            
            # Use new OpenAI API v1.0+ format
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.2,  # Use low temperature for more consistent, deterministic outputs
                max_tokens=2000
            )
            
            # Extract response using new API format
            return response.choices[0].message.content
            
        except Exception as e:
            logger.exception(f"Error getting OpenAI response: {str(e)}")
            raise
    
    def _get_ollama_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Get response from Ollama API"""
        try:
            url = f"{self.base_url}/api/generate"
            
            payload = {
                "model": self.model,
                "prompt": prompt
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            response = requests.post(url, json=payload)
            response.raise_for_status()
            
            result = response.json()
            return result.get('response', '')
        except Exception as e:
            logger.exception(f"Error getting Ollama response: {str(e)}")
            raise
    
    def _create_vulnerability_analysis_prompt(self, scan_data: Dict[str, Any]) -> str:
        """
        Create a detailed prompt for vulnerability analysis with score alignment
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            Formatted prompt string
        """
        prompt = """Analyze the following website security scan results to identify vulnerabilities and security issues.

    IMPORTANT: A technical security scanner has already calculated a baseline security score. Please provide your expert analysis 
    while considering this baseline, but you may adjust the score based on your cybersecurity expertise and risk assessment.

    Provide a structured response with:
    1. A list of identified vulnerabilities
    2. The severity level for each (Critical, High, Medium, Low)
    3. A brief description of each vulnerability
    4. An overall security risk assessment
    5. A security score that considers both technical findings and business risk

    Scan results:
    """
        
        # Add target information
        if 'target_url' in scan_data:
            prompt += f"\nTarget URL: {scan_data['target_url']}\n"
        
        # Add scanner's security score as context for AI
        if 'security_score' in scan_data:
            prompt += f"Technical Scanner Score: {scan_data['security_score']}/100\n"
        
        # Add overall findings summary if available
        if 'findings_summary' in scan_data:
            summary = scan_data['findings_summary']
            prompt += f"Findings Summary: {summary.get('high', 0)} high, {summary.get('medium', 0)} medium, {summary.get('low', 0)} low findings\n"
        
        # Add header information if available
        if 'headers' in scan_data:
            prompt += "\nHTTP Headers:\n"
            for header, value in scan_data['headers'].items():
                prompt += f"{header}: {value}\n"
        
        # Add SSL information if available
        if 'ssl_info' in scan_data:
            prompt += "\nSSL/TLS Information:\n"
            ssl_info = scan_data['ssl_info']
            for key, value in ssl_info.items():
                prompt += f"{key}: {value}\n"
        
        # Add vulnerability information if already identified
        if 'vulnerabilities' in scan_data:
            prompt += "\nAlready Identified Vulnerabilities:\n"
            for vuln in scan_data['vulnerabilities']:
                prompt += f"- {vuln.get('name', 'Unknown')}: {vuln.get('description', 'No description')}\n"
        
        # Add any scan results
        if 'results' in scan_data:
            prompt += "\nScan Results:\n"
            for result in scan_data['results']:
                name = result.get('name', 'Unknown')
                category = result.get('category', 'Unknown')
                severity = result.get('severity', 'Unknown')
                prompt += f"- {name} ({category}, {severity})\n"
                if 'details' in result:
                    prompt += f"  Details: {json.dumps(result['details'], indent=2)[:500]}...\n"
        
        # Request format for response
        prompt += """
    Please provide your analysis in the following JSON format:
    {
    "vulnerabilities": [
        {
        "name": "Vulnerability name",
        "description": "Brief description",
        "severity": "Critical|High|Medium|Low",
        "impact": "Impact description"
        }
    ],
    "risk_level": "Critical|High|Medium|Low",
    "security_score": 47,
    "score_reasoning": "Brief explanation of your security score assessment, mentioning if you agree with the technical scanner or why you adjusted it",
    "risk_summary": "Brief overall risk assessment"
    }

    SCORING GUIDANCE:
    - Consider the technical scanner's baseline score as a starting point
    - Adjust based on business impact, exploitability, and real-world risk
    - Explain any significant differences from the technical score in score_reasoning
    - For test sites like badssl.com, scores should reflect their intentionally insecure nature
    """
        
        return prompt
    
    def _create_recommendations_prompt(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Create a prompt for generating security recommendations
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Formatted prompt string
        """
        prompt = """Based on the following identified vulnerabilities, provide specific, actionable security recommendations:

Vulnerabilities:
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            name = vuln.get('name', 'Unknown vulnerability')
            description = vuln.get('description', 'No description')
            severity = vuln.get('severity', 'Unknown')
            impact = vuln.get('impact', 'Unknown impact')
            
            prompt += f"{i}. {name}\n"
            prompt += f"   Severity: {severity}\n"
            prompt += f"   Description: {description}\n"
            if impact:
                prompt += f"   Impact: {impact}\n"
            prompt += "\n"
        
        prompt += """
For each vulnerability, provide a recommendation in the following JSON format:
{
  "recommendations": [
    {
      "title": "Brief recommendation title",
      "description": "Description of the security issue",
      "severity": "critical|high|medium|low",
      "recommendation": "Detailed step-by-step remediation instructions",
      "references": "Relevant security standards or best practices",
      "confidence_score": 0.95 (a number between 0 and 1)
    }
  ]
}
"""
        
        return prompt
    
    def _create_executive_summary_prompt(self, scan_results: Dict[str, Any]) -> str:
        """
        Create a prompt for generating an executive summary
        
        Args:
            scan_results: Complete scan results with analysis
            
        Returns:
            Formatted prompt string
        """
        prompt = """Generate a concise executive summary of the following website security scan results.
The summary should be suitable for presentation to non-technical executives and should include:
1. Overall security posture assessment
2. Key risks and their potential business impact
3. Top priority recommendations
4. Key strengths (if any)

Scan Results:
"""
        
        # Add target information
        target_url = scan_results.get('target_url', 'Unknown')
        prompt += f"\nTarget URL: {target_url}\n"
        
        # Add overall risk level if available
        risk_level = scan_results.get('risk_level', 'Unknown')
        prompt += f"Overall Risk Level: {risk_level}\n"
        
        # Add vulnerability summary if available
        vulnerabilities = scan_results.get('vulnerabilities', [])
        prompt += f"Total Vulnerabilities: {len(vulnerabilities)}\n"
        
        if vulnerabilities:
            # Count vulnerabilities by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            prompt += "Vulnerabilities by Severity:\n"
            for severity, count in severity_counts.items():
                prompt += f"- {severity}: {count}\n"
            
            # Add top vulnerabilities
            prompt += "\nTop Vulnerabilities:\n"
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                name = vuln.get('name', 'Unknown')
                severity = vuln.get('severity', 'Unknown')
                prompt += f"{i}. {name} ({severity})\n"
        
        # Add recommendations summary if available
        recommendations = scan_results.get('recommendations', [])
        if recommendations:
            prompt += f"\nTop Recommendations:\n"
            for i, rec in enumerate(recommendations[:3], 1):
                title = rec.get('title', 'Unknown')
                prompt += f"{i}. {title}\n"
        
        # Request format
        prompt += """
Please provide a 3-4 paragraph executive summary that is:
- Concise and to the point
- Written in business language rather than technical jargon
- Focused on business impact and risk rather than technical details
- Actionable, with clear prioritization
"""
        
        return prompt
    
    def _parse_vulnerability_analysis(self, response: str) -> Dict[str, Any]:
        """
        Parse the LLM response into structured vulnerability analysis
        
        Args:
            response: Text response from LLM
            
        Returns:
            Structured vulnerability analysis dictionary
        """
        try:
            # Try to extract JSON from the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                analysis = json.loads(json_str)
                return analysis
            
            # If JSON parsing fails, try to extract information using heuristics
            lines = response.split('\n')
            vulnerabilities = []
            risk_level = "Medium"  # Default
            risk_summary = ""
            
            current_vuln = None
            in_vulnerability_section = False
            in_risk_section = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Look for section headers
                if "vulnerability" in line.lower() and ":" in line:
                    in_vulnerability_section = True
                    in_risk_section = False
                    
                    if current_vuln and 'name' in current_vuln:
                        vulnerabilities.append(current_vuln)
                    
                    current_vuln = {
                        'name': line.split(":", 1)[0].strip(),
                        'description': line.split(":", 1)[1].strip() if ":" in line else ""
                    }
                elif "severity" in line.lower() and ":" in line and current_vuln:
                    value = line.split(":", 1)[1].strip()
                    current_vuln['severity'] = value
                elif "impact" in line.lower() and ":" in line and current_vuln:
                    value = line.split(":", 1)[1].strip()
                    current_vuln['impact'] = value
                elif "description" in line.lower() and ":" in line and current_vuln:
                    value = line.split(":", 1)[1].strip()
                    current_vuln['description'] = value
                elif "risk" in line.lower() and "level" in line.lower() and ":" in line:
                    in_vulnerability_section = False
                    in_risk_section = True
                    
                    value = line.split(":", 1)[1].strip()
                    risk_level = value
                elif "risk" in line.lower() and "summary" in line.lower() and ":" in line:
                    in_vulnerability_section = False
                    in_risk_section = True
                    
                    value = line.split(":", 1)[1].strip()
                    risk_summary = value
                elif in_vulnerability_section and current_vuln:
                    # Add to the description of the current vulnerability
                    if 'description' in current_vuln:
                        current_vuln['description'] += " " + line
                    else:
                        current_vuln['description'] = line
                elif in_risk_section:
                    # Add to the risk summary
                    risk_summary += " " + line
            
            # Add the last vulnerability if exists
            if current_vuln and 'name' in current_vuln:
                vulnerabilities.append(current_vuln)
            
            # Ensure each vulnerability has a severity
            for vuln in vulnerabilities:
                if 'severity' not in vuln:
                    # Try to infer severity from the name or description
                    text = (vuln.get('name', '') + ' ' + vuln.get('description', '')).lower()
                    if 'critical' in text:
                        vuln['severity'] = 'Critical'
                    elif 'high' in text:
                        vuln['severity'] = 'High'
                    elif 'medium' in text:
                        vuln['severity'] = 'Medium'
                    elif 'low' in text:
                        vuln['severity'] = 'Low'
                    else:
                        vuln['severity'] = 'Medium'  # Default
            
            return {
                "vulnerabilities": vulnerabilities,
                "risk_level": risk_level,
                "risk_summary": risk_summary
            }
        except Exception as e:
            logger.exception(f"Error parsing vulnerability analysis: {str(e)}")
            return {
                "error": f"Failed to parse analysis: {str(e)}",
                "raw_response": response,
                "vulnerabilities": [],
                "risk_level": "Unknown"
            }
    
    def _parse_recommendations(self, response: str) -> List[Dict[str, Any]]:
        """
        Parse the LLM response into structured recommendations
        
        Args:
            response: Text response from LLM
            
        Returns:
            List of recommendation dictionaries
        """
        try:
            # Try to extract JSON from the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                result = json.loads(json_str)
                
                if 'recommendations' in result and isinstance(result['recommendations'], list):
                    return result['recommendations']
            
            # If JSON parsing fails, try to extract information using heuristics
            lines = response.split('\n')
            recommendations = []
            
            current_rec = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Look for numbered recommendations or section headers
                if line.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
                    if current_rec and 'title' in current_rec:
                        recommendations.append(current_rec)
                    
                    title = line.split(".", 1)[1].strip() if "." in line else line
                    current_rec = {'title': title}
                elif "title:" in line.lower():
                    if current_rec and 'title' in current_rec:
                        recommendations.append(current_rec)
                    
                    value = line.split(":", 1)[1].strip()
                    current_rec = {'title': value}
                elif "description:" in line.lower() and current_rec:
                    value = line.split(":", 1)[1].strip()
                    current_rec['description'] = value
                elif "severity:" in line.lower() and current_rec:
                    value = line.split(":", 1)[1].strip().lower()
                    current_rec['severity'] = value
                elif "recommendation:" in line.lower() and current_rec:
                    value = line.split(":", 1)[1].strip()
                    current_rec['recommendation'] = value
                elif "references:" in line.lower() and current_rec:
                    value = line.split(":", 1)[1].strip()
                    current_rec['references'] = value
                elif "confidence" in line.lower() and "score" in line.lower() and ":" in line and current_rec:
                    value_str = line.split(":", 1)[1].strip()
                    try:
                        value = float(value_str)
                        current_rec['confidence_score'] = value
                    except ValueError:
                        current_rec['confidence_score'] = 0.8  # Default
                elif current_rec:
                    # Add to the previous field if one exists
                    for field in ['recommendation', 'description', 'references']:
                        if field in current_rec:
                            current_rec[field] += " " + line
                            break
            
            # Add the last recommendation if exists
            if current_rec and 'title' in current_rec:
                recommendations.append(current_rec)
            
            # Ensure each recommendation has all required fields
            for rec in recommendations:
                if 'description' not in rec:
                    rec['description'] = rec.get('title', '')
                
                if 'severity' not in rec:
                    # Try to infer severity from the title or description
                    text = (rec.get('title', '') + ' ' + rec.get('description', '')).lower()
                    if 'critical' in text:
                        rec['severity'] = 'critical'
                    elif 'high' in text:
                        rec['severity'] = 'high'
                    elif 'medium' in text:
                        rec['severity'] = 'medium'
                    elif 'low' in text:
                        rec['severity'] = 'low'
                    else:
                        rec['severity'] = 'medium'  # Default
                
                if 'recommendation' not in rec:
                    rec['recommendation'] = "No specific recommendation provided."
                
                if 'confidence_score' not in rec:
                    rec['confidence_score'] = 0.8  # Default
            
            return recommendations
            
        except Exception as e:
            logger.exception(f"Error parsing recommendations: {str(e)}")
            return [{
                "title": "Error parsing recommendations",
                "description": f"An error occurred: {str(e)}",
                "severity": "medium",
                "recommendation": "Please try running the analysis again.",
                "confidence_score": 0.5
            }]