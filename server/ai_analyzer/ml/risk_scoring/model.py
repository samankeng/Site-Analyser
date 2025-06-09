# backend/ai_analyzer/ml/risk_scoring/model.py

import logging
import numpy as np
import json
import os
from django.conf import settings

logger = logging.getLogger(__name__)

class RiskScoringModel:
    """
    Risk scoring model for calculating security risk scores based on scan results
    Uses a weighted scoring system that can be customized for different security needs
    """
    
    def __init__(self):
        # Load scoring weights from settings or use defaults
        self.weights_path = os.path.join(
            getattr(settings, 'ML_MODELS_DIR', 'ml_models'),
            'risk_scoring',
            'weights.json'
        )
        self.initialize_weights()
    
    def initialize_weights(self):
        """Initialize risk scoring weights"""
        try:
            if os.path.exists(self.weights_path):
                # Load weights from file
                with open(self.weights_path, 'r') as f:
                    self.weights = json.load(f)
                logger.info("Loaded risk scoring weights from disk")
            else:
                # Use default weights
                logger.info("No saved weights found, using default risk scoring weights")
                self.weights = self._get_default_weights()
                
                # Save default weights
                self._save_weights()
        except Exception as e:
            logger.error(f"Error initializing risk scoring weights: {str(e)}")
            # Fall back to default weights
            self.weights = self._get_default_weights()
    
    def _get_default_weights(self):
        """Get default scoring weights for different components"""
        return {
            # Category weights (must sum to 1.0)
            "category_weights": {
                "headers": 0.25,
                "ssl": 0.30,
                "vulnerabilities": 0.35,
                "content": 0.10
            },
            
            # Severity deductions (amount to deduct from score)
            "severity_deductions": {
                "critical": 15,
                "high": 8,
                "medium": 4,
                "low": 1,
                "info": 0
            },
            
            # Score thresholds for overall severity rating
            "severity_thresholds": {
                "critical": 50,
                "high": 70,
                "medium": 85,
                "low": 95
            }
        }
    
    def _save_weights(self):
        """Save current weights to disk"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.weights_path), exist_ok=True)
            
            # Save weights
            with open(self.weights_path, 'w') as f:
                json.dump(self.weights, f, indent=4)
            logger.info("Saved risk scoring weights to disk")
            return True
        except Exception as e:
            logger.error(f"Error saving risk scoring weights: {str(e)}")
            return False
    
    def calculate_risk_score(self, scan_data):
        """
        Calculate security risk score from scan data
        
        Args:
            scan_data (dict): Dictionary with categorized scan results and findings
            
        Returns:
            dict: Risk scoring results including overall and category scores
        """
        logger.info("Calculating risk score for scan data")
        
        # Initialize category scores
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
        
        # Process all findings by category
        for category, findings in scan_data.items():
            if category not in category_scores:
                logger.warning(f"Skipping unknown category: {category}")
                continue
            
            # Calculate category score
            category_scores[category] = self._calculate_category_score(category, findings, severity_counts)
        
        # Calculate overall score (weighted average)
        overall_score = self._calculate_overall_score(category_scores)
        
        # Generate improvement suggestions
        suggestions = self._generate_improvement_suggestions(category_scores, severity_counts)
        
        return {
            'overall_score': overall_score,
            'category_scores': category_scores,
            'severity_counts': severity_counts,
            'improvement_suggestions': suggestions,
            'overall_severity': self._get_severity_from_score(overall_score)
        }
    
    def _calculate_category_score(self, category, findings, severity_counts):
        """Calculate score for a single category"""
        if not findings:
            logger.debug(f"No findings for category {category}, assigning perfect score")
            return 100  # Perfect score if no findings
        
        # Start with perfect score
        score = 100
        
        # Process each finding
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            
            # Update severity count
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Apply deduction based on severity
            deduction = self.weights["severity_deductions"].get(severity, 0)
            score -= deduction
        
        # Ensure score is between 0 and 100
        return max(0, min(100, score))
    
    def _calculate_overall_score(self, category_scores):
        """Calculate overall score from category scores"""
        category_weights = self.weights["category_weights"]
        overall_score = 0
        total_weight = 0
        
        for category, score in category_scores.items():
            if category in category_weights:
                weight = category_weights[category]
                overall_score += score * weight
                total_weight += weight
        
        # Normalize if weights don't sum to 1
        if total_weight > 0:
            overall_score = overall_score / total_weight
        
        return round(overall_score)
    
    def _generate_improvement_suggestions(self, category_scores, severity_counts):
        """Generate improvement suggestions based on scores"""
        suggestions = []
        
        # Add category-specific suggestions for low scores
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
        """Convert numerical score to severity rating"""
        thresholds = self.weights["severity_thresholds"]
        
        if score < thresholds.get("critical", 50):
            return "critical"
        elif score < thresholds.get("high", 70):
            return "high"
        elif score < thresholds.get("medium", 85):
            return "medium"
        elif score < thresholds.get("low", 95):
            return "low"
        else:
            return "info"
    
    def update_weights(self, new_weights):
        """
        Update scoring weights
        
        Args:
            new_weights (dict): New weights to use for scoring
            
        Returns:
            bool: True if weights were updated successfully
        """
        try:
            # Validate weights
            if not self._validate_weights(new_weights):
                logger.error("Invalid weights provided")
                return False
            
            # Update weights
            self.weights.update(new_weights)
            
            # Save updated weights
            return self._save_weights()
            
        except Exception as e:
            logger.error(f"Error updating risk scoring weights: {str(e)}")
            return False
    
    def _validate_weights(self, weights):
        """Validate that weights are properly formatted"""
        # Check category weights
        if "category_weights" in weights:
            category_weights = weights["category_weights"]
            
            # Check if weights are numbers
            for category, weight in category_weights.items():
                if not isinstance(weight, (int, float)) or weight < 0:
                    logger.error(f"Invalid weight for category {category}: {weight}")
                    return False
            
            # Check if weights sum to approximately 1
            total = sum(category_weights.values())
            if not (0.99 <= total <= 1.01):  # Allow for small floating point errors
                logger.error(f"Category weights must sum to 1.0, got {total}")
                return False
        
        # Check severity deductions
        if "severity_deductions" in weights:
            severity_deductions = weights["severity_deductions"]
            
            # Check if deductions are non-negative numbers
            for severity, deduction in severity_deductions.items():
                if not isinstance(deduction, (int, float)) or deduction < 0:
                    logger.error(f"Invalid deduction for severity {severity}: {deduction}")
                    return False
        
        # Check severity thresholds
        if "severity_thresholds" in weights:
            thresholds = weights["severity_thresholds"]
            
            # Check if thresholds are within range
            for severity, threshold in thresholds.items():
                if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 100:
                    logger.error(f"Invalid threshold for severity {severity}: {threshold}")
                    return False
            
            # Check if thresholds are in correct order
            if ("critical" in thresholds and "high" in thresholds and
                thresholds["critical"] >= thresholds["high"]):
                logger.error("Critical threshold must be lower than high threshold")
                return False
            
            if ("high" in thresholds and "medium" in thresholds and
                thresholds["high"] >= thresholds["medium"]):
                logger.error("High threshold must be lower than medium threshold")
                return False
            
            if ("medium" in thresholds and "low" in thresholds and
                thresholds["medium"] >= thresholds["low"]):
                logger.error("Medium threshold must be lower than low threshold")
                return False
        
        return True