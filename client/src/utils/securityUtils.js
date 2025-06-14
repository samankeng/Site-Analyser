// frontend/src/utils/securityUtils.js

/**
 * Detailed, consistent security score calculation
 * @param {Array|Object} results - Raw scan results or severity counts
 * @returns {Number} Security score from 0-100
 */
// export const calculateSecurityScore = (results) => {
//   const severityWeights = {
//     critical: 15,
//     high: 8,
//     medium: 4,
//     low: 1,
//     info: 0,
//   };

//   let severityCounts;

//   if (Array.isArray(results)) {
//     if (results.length === 0) return null; // <== FIX HERE
//     severityCounts = results.reduce(
//       (counts, result) => {
//         const severity = (result.severity || "info").toLowerCase();
//         counts[severity] = (counts[severity] || 0) + 1;
//         return counts;
//       },
//       { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
//     );
//   } else if (typeof results === "object") {
//     const totalCount = Object.values(results).reduce((a, b) => a + b, 0);
//     if (totalCount === 0) return null; // <== FIX HERE

//     severityCounts = {
//       critical: results.critical || 0,
//       high: results.high || 0,
//       medium: results.medium || 0,
//       low: results.low || 0,
//       info: results.info || 0,
//     };
//   } else {
//     return null;
//   }

//   const totalDeduction = Object.entries(severityCounts).reduce(
//     (total, [severity, count]) =>
//       total + count * (severityWeights[severity] || 0),
//     0
//   );

//   return Math.max(0, 100 - Math.min(100, totalDeduction));
// };

export const calculateSecurityScore = (results) => {
  const severityWeights = {
    critical: 15,
    high: 8,
    medium: 4,
    low: 0.5,
    info: 0,
  };

  // Max total deduction allowed per severity
  const maxDeductionPerSeverity = {
    critical: 60,
    high: 40,
    medium: 30,
    low: 15,
    info: 0,
  };

  let severityCounts;

  if (Array.isArray(results)) {
    if (results.length === 0) return null;
    severityCounts = results.reduce(
      (counts, result) => {
        const severity = (result.severity || "info").toLowerCase();
        counts[severity] = (counts[severity] || 0) + 1;
        return counts;
      },
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    );
  } else if (typeof results === "object") {
    const totalCount = Object.values(results).reduce((a, b) => a + b, 0);
    if (totalCount === 0) return null;

    severityCounts = {
      critical: results.critical || 0,
      high: results.high || 0,
      medium: results.medium || 0,
      low: results.low || 0,
      info: results.info || 0,
    };
  } else {
    return null;
  }

  // Apply capped total deduction
  const totalDeduction = Object.entries(severityCounts).reduce(
    (total, [severity, count]) => {
      const deduction = count * (severityWeights[severity] || 0);
      const cappedDeduction = Math.min(
        deduction,
        maxDeductionPerSeverity[severity] || 0
      );
      return total + cappedDeduction;
    },
    0
  );

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
