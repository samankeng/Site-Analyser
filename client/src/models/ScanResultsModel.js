// frontend/src/models/ScanResultsModel.js

import { 
  calculateSecurityScore, 
  countSeverities, 
  countCategories,
  getSecurityRating,
  getHighestSeverity
} from '../utils/securityUtils';

/**
 * Processes and standardizes scan results data
 * @param {Object} scanData - Raw scan data
 * @param {Array} resultsData - Raw results data
 * @returns {Object} Processed scan results model
 */
export const processScanResults = (scanData, resultsData = []) => {
  // Handle missing scan data
  if (!scanData) {
    return null;
  }
  
  // Normalize results data with consistent severity
  const normalizedResults = (resultsData || []).map(result => ({
    ...result,
    severity: (result.severity || 'info').toLowerCase(),
    category: (result.category || 'unknown').toLowerCase()
  }));
  
  // Ensure default severity if no results
  const defaultResults = normalizedResults.length > 0 
    ? normalizedResults 
    : [{ severity: 'info', category: 'unknown' }];
  
  // Count findings by severity with consistent defaults
  const severityCounts = countSeverities(defaultResults);
  
  // Count findings by category
  const categoryCounts = countCategories(defaultResults);
  
  // Calculate security score
  const securityScore = calculateSecurityScore(defaultResults);
  
  // Get highest severity level
  const highestSeverity = getHighestSeverity(severityCounts);
  
  // Get risk level text
  const riskLevel = getSecurityRating(securityScore);
  
  return {
    ...scanData,
    results: defaultResults,
    severityCounts,
    categoryCounts,
    securityScore,
    highestSeverity,
    riskLevel,
    totalFindings: defaultResults.length
  };
};

/**
 * Prepare data for dashboard display
 * @param {Array} scans - Raw scan data
 * @returns {Object} Processed dashboard metrics
 */
export const prepareDashboardMetrics = (scans = []) => {
  // Calculate overall vulnerability counts
  const overallVulnerabilityCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  // Aggregate scores
  const categoryScores = {
    headers: 100,
    ssl: 100,
    vulnerabilities: 100,
    content: 100
  };

  let totalScans = 0;
  let latestScore = 100;

  // Process each scan
  scans.forEach(scan => {
    if (scan.results && scan.results.length > 0) {
      totalScans++;
      
      // Aggregate severity counts
      scan.results.forEach(result => {
        const severity = (result.severity || 'info').toLowerCase();
        if (severity in overallVulnerabilityCounts) {
          overallVulnerabilityCounts[severity]++;
        }
      });

      // Update latest score (use the most recent scan's score)
      if (scan.securityScore !== undefined) {
        latestScore = scan.securityScore;
      }

      // Adjust category scores based on findings
      Object.keys(categoryScores).forEach(category => {
        const categoryResults = scan.results.filter(r => 
          r.category && r.category.toLowerCase() === category
        );
        
        if (categoryResults.length > 0) {
          categoryScores[category] = calculateSecurityScore(categoryResults);
        }
      });
    }
  });

  return {
    overallScore: latestScore,
    categoryScores,
    vulnerabilityCounts: overallVulnerabilityCounts,
    totalScans
  };
};