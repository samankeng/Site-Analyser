# ai_analyzer/services/specific_recommendations.py

import openai
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class SpecificRecommendationGenerator:
    """Generate specific, actionable recommendations using OpenAI"""
    
    def __init__(self):
        self.client = openai.OpenAI()
    
    def generate_specific_recommendations(self, issues: List[Dict], target_url: str) -> List[Dict]:
        """
        Generate specific recommendations for security issues using OpenAI
        
        Args:
            issues: List of security issues found
            target_url: The target URL being scanned
            
        Returns:
            List of enhanced recommendations with specific actions
        """
        recommendations = []
        
        # Group issues by category for better analysis
        categorized_issues = self._categorize_issues(issues)
        
        for category, category_issues in categorized_issues.items():
            try:
                specific_rec = self._generate_category_recommendation(
                    category, category_issues, target_url
                )
                if specific_rec:
                    recommendations.append(specific_rec)
                    logger.info(f"Generated specific recommendation for {category}")
                    
            except Exception as e:
                logger.error(f"Error generating recommendation for {category}: {str(e)}")
                # Fallback to generic recommendation
                generic_rec = self._create_generic_recommendation(category, category_issues)
                recommendations.append(generic_rec)
        
        return recommendations
    
    def _generate_category_recommendation(self, category: str, issues: List[Dict], target_url: str) -> Dict:
        """Generate specific recommendation for a category of issues"""
        
        # Create detailed context about the issues
        issue_context = self._create_issue_context(issues, target_url)
        
        prompt = f"""
You are a cybersecurity expert providing specific, actionable recommendations for web security issues.

CONTEXT:
- Target website: {target_url}
- Security category: {category}
- Issues found: {len(issues)}

SPECIFIC ISSUES DETAILS:
{issue_context}

TASK:
Generate a specific, actionable recommendation that includes:

1. EXACT technical details of what's wrong
2. SPECIFIC configuration changes needed (include exact headers/code)
3. STEP-BY-STEP implementation instructions
4. CODE EXAMPLES where applicable
5. PRIORITY level (Critical/High/Medium/Low)
6. ESTIMATED fix time
7. TESTING steps to verify the fix

FORMAT your response as JSON:
{{
    "title": "Specific title describing the exact fix needed",
    "severity": "critical|high|medium|low",
    "priority": "critical|high|medium|low", 
    "estimated_fix_time": "X minutes/hours",
    "technical_details": "Exact explanation of what's wrong",
    "specific_actions": [
        "Step 1: Exact action with code/configuration",
        "Step 2: Next specific step",
        "Step 3: etc."
    ],
    "code_examples": {{
        "apache": "Apache configuration example",
        "nginx": "Nginx configuration example", 
        "application": "Application-level code example"
    }},
    "verification_steps": [
        "How to test if the fix worked",
        "Tools to verify the configuration"
    ],
    "additional_resources": [
        "Relevant documentation links",
        "Security best practices"
    ],
    "confidence": 95
}}

Make the recommendations extremely specific and actionable. Avoid generic advice.
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in specific, actionable web security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistent, focused responses
                max_tokens=1500
            )
            
            # Parse the JSON response
            import json
            recommendation_json = response.choices[0].message.content
            
            # Clean up the response (remove markdown formatting if present)
            if "```json" in recommendation_json:
                recommendation_json = recommendation_json.split("```json")[1].split("```")[0]
            
            recommendation = json.loads(recommendation_json)
            
            # Add metadata
            recommendation.update({
                "category": category,
                "issues_addressed": len(issues),
                "target_url": target_url,
                "generated_by": "openai_specific",
                "timestamp": "2025-06-22T22:32:11Z"
            })
            
            return recommendation
            
        except Exception as e:
            logger.error(f"OpenAI API error for {category}: {str(e)}")
            return None
    
    def _create_issue_context(self, issues: List[Dict], target_url: str) -> str:
        """Create detailed context about the specific issues found"""
        context_parts = []
        
        for i, issue in enumerate(issues[:10], 1):  # Limit to top 10 issues
            issue_detail = f"""
Issue {i}:
- Name: {issue.get('name', 'Unknown')}
- Description: {issue.get('description', 'No description')}
- Severity: {issue.get('severity', 'unknown')}
- Details: {issue.get('details', {})}
- Found at: {issue.get('details', {}).get('page_url', target_url)}
"""
            context_parts.append(issue_detail)
        
        if len(issues) > 10:
            context_parts.append(f"\n... and {len(issues) - 10} more similar issues")
        
        return "\n".join(context_parts)
    
    def _categorize_issues(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by category"""
        categorized = {}
        
        for issue in issues:
            category = issue.get('category', 'general')
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(issue)
        
        return categorized
    
    def _create_generic_recommendation(self, category: str, issues: List[Dict]) -> Dict:
        """Fallback generic recommendation if OpenAI fails"""
        return {
            "title": f"Address {category.title()} Security Issues",
            "severity": "medium",
            "priority": "medium",
            "estimated_fix_time": "30-60 minutes",
            "technical_details": f"Found {len(issues)} {category} security issues that need attention.",
            "specific_actions": [
                f"Review and fix {category} configuration",
                "Implement security best practices",
                "Test the changes thoroughly"
            ],
            "confidence": 70,
            "generated_by": "fallback_generic"
        }