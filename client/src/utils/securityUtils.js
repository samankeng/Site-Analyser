// frontend/src/utils/securityUtils.js

/**
 * Detailed, consistent security score calculation
 * @param {Array|Object} results - Raw scan results or severity counts
 * @returns {Number} Security score from 0-100
 */
export const calculateSecurityScore = (results) => {
  const severityWeights = {
    critical: 20, // Most severe impact
    high: 10, // Significant risk
    medium: 5, // Moderate concern
    low: 2, // Minor issue
    info: 0, // Informational, no score reduction
  };

  let severityCounts;

  // Handle different input types
  if (Array.isArray(results)) {
    // If results are an array of objects, count severities
    severityCounts = results.reduce(
      (counts, result) => {
        const severity = (result.severity || "info").toLowerCase();
        counts[severity] = (counts[severity] || 0) + 1;
        return counts;
      },
      {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      }
    );
  } else if (typeof results === "object") {
    // If results are already a count object
    severityCounts = {
      critical: results.critical || 0,
      high: results.high || 0,
      medium: results.medium || 0,
      low: results.low || 0,
      info: results.info || 0,
    };
  } else {
    // Default to no findings
    return 100;
  }

  // Calculate total deduction
  const totalDeduction = Object.entries(severityCounts).reduce(
    (total, [severity, count]) =>
      total + count * (severityWeights[severity] || 0),
    0
  );

  // Ensure score doesn't go below 0
  return Math.max(0, 100 - Math.min(100, totalDeduction));
};

/**
 * Get a text-based security rating based on the score
 * @param {Number} score - Security score (0-100)
 * @returns {String} Risk level description
 */
export const getSecurityRating = (score) => {
  // Ensure score is a number and within range
  const safeScore = typeof score === "number" ? score : 100;

  if (safeScore >= 90) return "Very Secure";
  if (safeScore >= 80) return "Secure";
  if (safeScore >= 70) return "Moderately Secure";
  if (safeScore >= 60) return "Needs Improvement";
  if (safeScore >= 40) return "Insecure";
  return "Critically Insecure";
};

/**
 * Count findings by severity
 * @param {Array} results - Scan result items
 * @returns {Object} Counts by severity
 */
// export const countSeverities = (results) => {
//   const counts = {
//     'critical': 0,
//     'high': 0,
//     'medium': 0,
//     'low': 0,
//     'info': 0
//   };

//   results.forEach(result => {
//     const severity = (result.severity || 'info').toLowerCase();
//     if (severity in counts) {
//       counts[severity]++;
//     }
//   });

//   return counts;
// };
/**
 * Count findings by severity
 * @param {Array} results - Scan result items
 * @returns {Object} Counts by severity
 */
export const countSeverities = (results) => {
  const defaultSeverities = ["critical", "high", "medium", "low", "info"];
  const counts = Object.fromEntries(defaultSeverities.map((sev) => [sev, 0]));

  results.forEach((result) => {
    const severity = (result.severity || "info").toLowerCase().trim();
    if (counts.hasOwnProperty(severity)) {
      counts[severity]++;
    } else {
      // Log unknown severity for debugging
      console.warn("Unknown severity level encountered:", severity, result);
      counts[severity] = 1;
    }
  });

  return counts;
};

/**
 * Count findings by category
 * @param {Array} results - Scan result items
 * @returns {Object} Counts by category
 */
export const countCategories = (results) => {
  return results.reduce((acc, result) => {
    const category = (result.category || "unknown").toLowerCase();
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {});
};

/**
 * Determine the highest severity level
 * @param {Object} severityCounts - Counts by severity
 * @returns {String} Highest severity level
 */
export const getHighestSeverity = (severityCounts) => {
  const severityOrder = ["critical", "high", "medium", "low", "info", "none"];

  for (let severity of severityOrder) {
    if (severityCounts[severity] && severityCounts[severity] > 0) {
      return severity;
    }
  }

  return "none";
};

/**
 * CSS color mapping for security scores
 * @param {Number} score - Security score (0-100)
 * @returns {String} CSS color class
 */
export const getScoreColorClass = (score) => {
  if (score >= 90) return "text-success";
  if (score >= 70) return "text-info";
  if (score >= 50) return "text-warning";
  return "text-danger";
};

/**
 * Get the appropriate badge class for a severity level
 * @param {String} severity - Severity level
 * @returns {String} CSS badge class
 */
export const getSeverityBadgeClass = (severity) => {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return "bg-danger";
    case "high":
      return "bg-warning text-dark";
    case "medium":
      return "bg-info text-dark";
    case "low":
      return "bg-secondary";
    case "info":
      return "bg-light text-dark";
    default:
      return "bg-secondary";
  }
};

/**
 * Get the appropriate badge class for a status
 * @param {String} status - Status value
 * @returns {String} CSS badge class
 */
export const getStatusBadgeClass = (status) => {
  switch ((status || "").toLowerCase()) {
    case "completed":
      return "bg-success";
    case "pending":
      return "bg-warning text-dark";
    case "in_progress":
      return "bg-info text-dark";
    case "failed":
      return "bg-danger";
    default:
      return "bg-secondary";
  }
};
