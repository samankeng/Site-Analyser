// frontend/src/utils/securityUtils.js

/**
 * Calculates security score based on vulnerability counts
 * @param {Object} severityCounts - Object with counts by severity level
 * @returns {Number} Security score from 0-100
 */
export const calculateSecurityScore = (results) => {
  if (!results || !Array.isArray(results) || results.length === 0) return 100;

  const severityWeights = {
    'critical': 20,
    'high': 10,
    'medium': 5,
    'low': 2,
    'info': 0
  };

  // Count findings by severity
  const severityCounts = {};
  results.forEach(result => {
    const severity = result.severity.toLowerCase();
    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
  });

  // Calculate total deduction
  let totalDeduction = 0;
  Object.entries(severityCounts).forEach(([severity, count]) => {
    totalDeduction += count * (severityWeights[severity] || 0);
  });

  // Ensure score doesn't go below 0
  return Math.max(0, 100 - Math.min(100, totalDeduction));
};

/**
 * Gets the appropriate badge class for a status
 * @param {String} status - Status value
 * @returns {String} CSS class name
 */
export const getStatusBadgeClass = (status) => {
  switch (status) {
    case 'completed':
      return 'bg-success';
    case 'pending':
      return 'bg-warning text-dark';
    case 'in_progress':
      return 'bg-info text-dark';
    case 'failed':
      return 'bg-danger';
    default:
      return 'bg-secondary';
  }
};

/**
 * Gets the appropriate badge class for a severity level
 * @param {String} severity - Severity level
 * @returns {String} CSS class name
 */
export const getSeverityBadgeClass = (severity) => {
  switch (severity) {
    case 'critical':
      return 'bg-danger';
    case 'high':
      return 'bg-warning text-dark';
    case 'medium':
      return 'bg-info text-dark';
    case 'low':
      return 'bg-secondary';
    case 'info':
      return 'bg-light text-dark';
    default:
      return 'bg-secondary';
  }
};

/**
 * Gets the appropriate text color class for a security score
 * @param {Number} score - Security score (0-100)
 * @returns {String} CSS class name
 */
export const getScoreColorClass = (score) => {
  if (score >= 90) return 'text-success';
  if (score >= 70) return 'text-info';
  if (score >= 50) return 'text-warning';
  return 'text-danger';
};

/**
 * Gets a textual rating based on a security score
 * @param {Number} score - Security score (0-100)
 * @returns {String} Rating description
 */
export const getSecurityRating = (score) => {
  if (score >= 90) return "Very Secure";
  if (score >= 80) return "Secure";
  if (score >= 70) return "Moderately Secure";
  if (score >= 60) return "Needs Improvement";
  if (score >= 40) return "Insecure";
  return "Critically Insecure";
};

/**
 * Counts findings by severity from scan results
 * @param {Array} results - Scan result items
 * @returns {Object} Counts by severity
 */
export const countSeverities = (results) => {
  return results.reduce((acc, result) => {
    acc[result.severity] = (acc[result.severity] || 0) + 1;
    return acc;
  }, {});
};

/**
 * Counts findings by category from scan results
 * @param {Array} results - Scan result items
 * @returns {Object} Counts by category
 */
export const countCategories = (results) => {
  return results.reduce((acc, result) => {
    acc[result.category] = (acc[result.category] || 0) + 1;
    return acc;
  }, {});
};