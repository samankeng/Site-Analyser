# server/ai_analyzer/services/ollama_client.py

import json
import logging
import requests
from typing import Dict, List, Any, Optional
from django.conf import settings

logger = logging.getLogger(__name__)

class OllamaClient:
    """Client for interacting with Ollama API for local LLM inference."""
    
    def __init__(self):
        """Initialize the Ollama client with settings."""
        self.base_url = settings.OLLAMA_BASE_URL
        self.model = settings.OLLAMA_MODEL_NAME
    
    def _generate_completion(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate a text completion using Ollama API.
        
        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt to set context
            
        Returns:
            Generated text response
        """
        url = f"{self.base_url}/api/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt
        }
        
        # Add system prompt if provided
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            
            # Parse the response
            result = response.json()
            return result.get('response', '')
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Ollama API: {str(e)}")
            raise
    
    def analyze_vulnerabilities(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results using Ollama to identify security vulnerabilities.
        
        Args:
            scan_data: Dictionary containing scan results
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            # Format the prompt with scan data (same as OpenAI client)
            prompt = self._format_vulnerability_prompt(scan_data)
            
            # Use system prompt to set context
            system_prompt = "You are a cybersecurity expert analyzing website vulnerabilities."
            
            # Call Ollama API
            response_text = self._generate_completion(prompt, system_prompt)
            
            # Parse and return the analysis
            return self._parse_vulnerability_analysis(response_text)
            
        except Exception as e:
            logger.error(f"Error during Ollama vulnerability analysis: {str(e)}")
            return {"error": str(e), "recommendations": [], "risk_level": "unknown"}
    
    def generate_security_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate specific security recommendations based on discovered vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of recommendation dictionaries
        """
        try:
            # Format the prompt with vulnerability data
            prompt = self._format_recommendation_prompt(vulnerabilities)
            
            # Set system prompt
            system_prompt = "You are a cybersecurity expert providing actionable recommendations."
            
            # Call Ollama API
            response_text = self._generate_completion(prompt, system_prompt)
            
            # Parse and return the recommendations
            return self._parse_recommendations(response_text)
            
        except Exception as e:
            logger.error(f"Error during Ollama recommendation generation: {str(e)}")
            return [{"error": str(e)}]
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze HTTP security headers using Ollama.
        
        Args:
            headers: Dictionary of HTTP headers
            
        Returns:
            Analysis of headers with recommendations
        """
        try:
            # Format headers for analysis
            headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            prompt = f"Analyze the following HTTP security headers and identify any missing or misconfigured headers:\n\n{headers_str}"
            
            # Set system prompt
            system_prompt = "You are a web security expert specializing in HTTP security headers."
            
            # Call Ollama API
            analysis = self._generate_completion(prompt, system_prompt)
            
            # Return structured analysis
            return {
                "analysis": analysis,
                "raw_headers": headers,
                "missing_headers": self._extract_missing_headers(analysis)
            }
            
        except Exception as e:
            logger.error(f"Error during Ollama header analysis: {str(e)}")
            return {"error": str(e)}
    
    # Helper methods - these can be identical to the OpenAI client implementation
    def _format_vulnerability_prompt(self, scan_data: Dict[str, Any]) -> str:
        """Format scan data into a prompt for vulnerability analysis."""
        prompt = "Analyze the following website scan results for security vulnerabilities:\n\n"
        
        # Add site info
        if "site_info" in scan_data:
            prompt += f"Site: {scan_data.get('site_info', {}).get('url', 'Unknown')}\n"
            prompt += f"Server: {scan_data.get('site_info', {}).get('server', 'Unknown')}\n\n"
        
        # Add headers
        if "headers" in scan_data:
            prompt += "HTTP Headers:\n"
            for key, value in scan_data["headers"].items():
                prompt += f"{key}: {value}\n"
            prompt += "\n"
        
        # Add SSL information
        if "ssl_info" in scan_data:
            prompt += "SSL Information:\n"
            prompt += f"Valid: {scan_data.get('ssl_info', {}).get('valid', False)}\n"
            prompt += f"Expires: {scan_data.get('ssl_info', {}).get('expires', 'Unknown')}\n"
            prompt += f"Grade: {scan_data.get('ssl_info', {}).get('grade', 'Unknown')}\n\n"
        
        # Add vulnerabilities if already identified
        if "vulnerabilities" in scan_data:
            prompt += "Identified Vulnerabilities:\n"
            for vuln in scan_data["vulnerabilities"]:
                prompt += f"- {vuln.get('name', 'Unknown')}: {vuln.get('description', 'No description')}\n"
        
        # Request format
        prompt += "\nProvide the following information in your analysis:\n"
        prompt += "1. A list of identified security vulnerabilities\n"
        prompt += "2. The severity level of each vulnerability (Critical, High, Medium, Low)\n"
        prompt += "3. An overall security risk assessment\n"
        prompt += "4. Top 3 most urgent security issues to address\n"
        
        return prompt
    
    def _parse_vulnerability_analysis(self, response_text: str) -> Dict[str, Any]:
        """Parse the Ollama response into structured vulnerability analysis."""
        content = response_text
        
        # Simple parsing - in a real app, use more robust parsing or structured outputs
        lines = content.split('\n')
        vulnerabilities = []
        risk_level = "Medium"  # Default
        
        current_section = ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Try to identify sections (simplistic approach)
            if "vulnerability" in line.lower() and ":" in line:
                parts = line.split(":", 1)
                vulnerabilities.append({
                    "name": parts[0].strip(),
                    "description": parts[1].strip(),
                    "severity": self._extract_severity(line)
                })
            
            if "risk assessment" in line.lower() and ":" in line:
                risk_part = line.split(":", 1)[1].strip()
                if any(level in risk_part.lower() for level in ["critical", "high", "medium", "low"]):
                    for level in ["Critical", "High", "Medium", "Low"]:
                        if level.lower() in risk_part.lower():
                            risk_level = level
                            break
        
        return {
            "vulnerabilities": vulnerabilities,
            "risk_level": risk_level,
            "raw_analysis": content
        }
    
    def _format_recommendation_prompt(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities into a prompt for generating recommendations."""
        prompt = "Based on the following identified vulnerabilities, provide specific, actionable security recommendations:\n\n"
        
        for i, vuln in enumerate(vulnerabilities, 1):
            prompt += f"{i}. {vuln.get('name', 'Unknown vulnerability')}"
            if "severity" in vuln:
                prompt += f" (Severity: {vuln['severity']})"
            prompt += "\n"
            
            if "description" in vuln:
                prompt += f"   Description: {vuln['description']}\n"
            prompt += "\n"
        
        prompt += "\nFor each vulnerability, provide:\n"
        prompt += "1. A concise description of the security risk\n"
        prompt += "2. Step-by-step remediation instructions\n"
        prompt += "3. References to relevant security standards (OWASP, NIST, etc.)\n"
        prompt += "4. Code examples where applicable\n"
        
        return prompt
    
    def _parse_recommendations(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse the Ollama response into structured recommendations."""
        content = response_text
        
        # In a real application, use more robust parsing
        # This is a simplified example
        recommendations = []
        current_rec = {}
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Start of a new recommendation
            if line.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
                if current_rec and "title" in current_rec:
                    recommendations.append(current_rec)
                current_rec = {"title": line.split(".", 1)[1].strip()}
            
            # Look for sections within a recommendation
            elif "risk:" in line.lower():
                current_rec["risk"] = line.split(":", 1)[1].strip()
            elif "remediation:" in line.lower():
                current_rec["remediation"] = line.split(":", 1)[1].strip()
            elif "references:" in line.lower():
                current_rec["references"] = line.split(":", 1)[1].strip()
            # Add content to the current section
            elif current_rec:
                # Append to the last added key
                if "remediation" in current_rec:
                    current_rec["remediation"] += " " + line
        
        # Add the last recommendation
        if current_rec and "title" in current_rec:
            recommendations.append(current_rec)
            
        return recommendations
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity level from text."""
        text_lower = text.lower()
        if "critical" in text_lower:
            return "Critical"
        elif "high" in text_lower:
            return "High"
        elif "medium" in text_lower:
            return "Medium"
        elif "low" in text_lower:
            return "Low"
        return "Unknown"
    
    def _extract_missing_headers(self, analysis: str) -> List[str]:
        """Extract missing security headers from analysis text."""
        missing = []
        common_headers = [
            "Content-Security-Policy",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "Referrer-Policy"
        ]
        
        for header in common_headers:
            if f"missing {header}" in analysis.lower() or f"{header} is missing" in analysis.lower():
                missing.append(header)
                
        return missing