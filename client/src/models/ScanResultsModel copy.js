// frontend/src/models/ScanResultsModel.js

import { 
  calculateSecurityScore, 
  countSeverities, 
  countCategories,
  getSecurityRating 
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
  
  // Count findings by severity
  const severityCounts = countSeverities(resultsData);
  
  // Count findings by category
  const categoryCounts = countCategories(resultsData);
  
  // Calculate security score
  const securityScore = calculateSecurityScore(resultsData);
  
  // Get highest severity level
  const highestSeverity = getHighestSeverity(severityCounts);
  
  // Get risk level text
  const riskLevel = getSecurityRating(securityScore);
  
  return {
    ...scanData,
    results: resultsData,
    severityCounts,
    categoryCounts,
    securityScore,
    highestSeverity,
    riskLevel,
    totalFindings: resultsData.length
  };
};

/**
 * Determines the highest severity level in the results
 * @param {Object} severityCounts - Counts by severity
 * @returns {String} Highest severity level
 */
const getHighestSeverity = (severityCounts) => {
  if (severityCounts.critical && severityCounts.critical > 0) return 'critical';
  if (severityCounts.high && severityCounts.high > 0) return 'high';
  if (severityCounts.medium && severityCounts.medium > 0) return 'medium';
  if (severityCounts.low && severityCounts.low > 0) return 'low';
  if (severityCounts.info && severityCounts.info > 0) return 'info';
  return 'none';
};