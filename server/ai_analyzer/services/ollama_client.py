# backend/ai_analyzer/services/ollama_client.py

import json
import logging
import os
import requests
from django.conf import settings
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class OllamaClient:
    """Client for interacting with Ollama API for LLM inference"""
    
    def __init__(self):
        # Get Ollama API settings from Django settings or environment variables
        self.api_base_url = getattr(settings, 'OLLAMA_API_URL', os.environ.get('OLLAMA_API_URL', 'http://ollama:11434'))
        self.default_model = getattr(settings, 'OLLAMA_DEFAULT_MODEL', os.environ.get('OLLAMA_DEFAULT_MODEL', 'llama2'))
        self.timeout = getattr(settings, 'OLLAMA_TIMEOUT', int(os.environ.get('OLLAMA_TIMEOUT', 30)))
    
    def generate(self, prompt, model=None, temperature=0.7, max_tokens=1024):
        """
        Generate text completion using Ollama API
        
        Args:
            prompt (str): The prompt to send to the LLM
            model (str, optional): The model to use. Defaults to self.default_model.
            temperature (float, optional): Controls randomness. Defaults to 0.7.
            max_tokens (int, optional): Maximum tokens to generate. Defaults to 1024.
            
        Returns:
            dict: API response containing generated text
        """
        if model is None:
            model = self.default_model
            
        logger.info(f"Generating completion with model {model}")
        
        api_url = urljoin(self.api_base_url, "/api/generate")
        
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Ollama API: {str(e)}")
            return {
                "error": str(e),
                "generated_text": None
            }
    
    def analyze_security_data(self, scan_data, scan_type):
        """
        Analyze security scan data using LLM
        
        Args:
            scan_data (dict): The security scan data to analyze
            scan_type (str): Type of scan (headers, ssl, vulnerability, etc.)
            
        Returns:
            dict: Analysis results from the LLM
        """
        prompt = self._build_security_analysis_prompt(scan_data, scan_type)
        
        # Get response from LLM
        response = self.generate(prompt, temperature=0.2)  # Lower temperature for more deterministic results
        
        if "error" in response:
            logger.error(f"Error generating security analysis: {response['error']}")
            return {"error": response["error"]}
        
        return self._parse_security_analysis_response(response)
    
    def _build_security_analysis_prompt(self, scan_data, scan_type):
        """Build prompt for security analysis"""
        # Convert scan data to string format
        scan_data_str = json.dumps(scan_data, indent=2)
        
        prompt = f"""
        You are an expert security analyst. Analyze the following {scan_type} scan data and provide an assessment.
        
        Include:
        1. Security issues found
        2. Severity rating for each issue (Critical, High, Medium, Low, Info)
        3. Specific recommendations to fix each issue
        4. An overall security score (0-100)
        
        Scan data:
        {scan_data_str}
        
        Format your response as JSON with the following structure:
        {{
            "issues": [
                {{
                    "name": "Issue name",
                    "description": "Detailed description",
                    "severity": "High/Medium/Low/Info",
                    "recommendation": "How to fix it"
                }}
            ],
            "overall_score": 80,
            "summary": "Brief security assessment summary"
        }}
        """
        
        return prompt
    
    def _parse_security_analysis_response(self, response):
        """Parse LLM response into structured format"""
        try:
            # Extract JSON from response
            text = response.get("response", "")
            
            # Find JSON in the response
            json_start = text.find('{')
            json_end = text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = text[json_start:json_end]
                analysis = json.loads(json_str)
                return analysis
            else:
                # If no JSON found, try to extract insights anyway
                return {
                    "issues": [],
                    "overall_score": 50,  # Default middle score
                    "summary": text[:500]  # Use first 500 chars as summary
                }
                
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error parsing LLM response: {str(e)}")
            return {
                "error": "Failed to parse LLM response",
                "raw_response": response.get("response", "")
            }
    
    def get_available_models(self):
        """Get list of available models from Ollama"""
        api_url = urljoin(self.api_base_url, "/api/tags")
        
        try:
            response = requests.get(api_url, timeout=self.timeout)
            response.raise_for_status()
            
            models_data = response.json()
            return models_data.get("models", [])
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching available models: {str(e)}")
            return []