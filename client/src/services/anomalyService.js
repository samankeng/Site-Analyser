// src/services/anomalyService.js

import api from "./api";

// Create the service object with all required methods
const anomalyService = {
  // Enhanced method to get anomalies for a scan with fallback detection
  getAnomaliesForScan: async (scanId) => {
    // Validate scanId before making API call
    if (!scanId || scanId === "undefined") {
      console.error("Invalid scanId provided to getAnomaliesForScan:", scanId);
      return { success: false, error: "Invalid scan ID" };
    }

    try {
      // Use proper URL structure matching the backend API
      const response = await api.get(
        `/ai-analyzer/anomalies/for_scan/?scan_id=${scanId}`
      );
      console.log("Get anomalies response:", response); // Debug log

      // Fix for API response format issue:
      // Ensure we're returning an array even if the API returns an object
      let anomaliesData = response.data;

      // Check if the response is an object with a results or items property containing the anomalies
      if (!Array.isArray(anomaliesData) && typeof anomaliesData === "object") {
        if (Array.isArray(anomaliesData.results)) {
          anomaliesData = anomaliesData.results;
        } else if (Array.isArray(anomaliesData.items)) {
          anomaliesData = anomaliesData.items;
        } else if (
          Object.keys(anomaliesData).length > 0 &&
          typeof anomaliesData.id === "string"
        ) {
          // If it's a single object with an ID, wrap it in an array
          anomaliesData = [anomaliesData];
        } else {
          // If we can't determine the format, assume empty array
          console.warn(
            "Unknown API response format for anomalies, defaulting to empty array"
          );
          anomaliesData = [];
        }
      }

      // If no anomalies detected from API, try to detect from scan results
      if (!anomaliesData || anomaliesData.length === 0) {
        console.log(
          "No API anomalies found, checking scan results for connection issues..."
        );
        try {
          const scanResults =
            await anomalyService.getScanResultsForAnomalyDetection(scanId);
          if (scanResults && scanResults.length > 0) {
            const detectedAnomalies =
              anomalyService.detectConnectionAnomalies(scanResults);
            if (detectedAnomalies.length > 0) {
              console.log(
                "Detected connection-based anomalies:",
                detectedAnomalies
              );
              anomaliesData = detectedAnomalies;
            }
          }
        } catch (scanError) {
          console.warn(
            "Could not fetch scan results for anomaly detection:",
            scanError
          );
        }
      }

      return { success: true, data: anomaliesData || [] };
    } catch (error) {
      console.error("Error in getAnomaliesForScan:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.response?.data ||
          error.message ||
          "Unknown error",
      };
    }
  },

  // New method to get scan results for anomaly detection
  getScanResultsForAnomalyDetection: async (scanId) => {
    try {
      // Try multiple endpoints to get scan results
      let response;
      try {
        response = await api.get(`/scanner/scans/${scanId}/results/`);
      } catch (error) {
        // Fallback to alternative endpoint
        try {
          response = await api.get(`/scanner/scans/${scanId}/results/`);
        } catch (fallbackError) {
          // Final fallback - get scan details and extract results
          const scanResponse = await api.get(`/scans/${scanId}/`);
          if (scanResponse.data && scanResponse.data.results) {
            return scanResponse.data.results;
          }
          throw fallbackError;
        }
      }

      return response.data;
    } catch (error) {
      console.error(
        "Error fetching scan results for anomaly detection:",
        error
      );
      return null;
    }
  },

  // Enhanced connection anomaly detection
  detectConnectionAnomalies: (scanResults) => {
    const anomalies = [];

    if (!Array.isArray(scanResults)) {
      console.warn("Invalid scan results format for anomaly detection");
      return anomalies;
    }

    console.log(
      `Analyzing ${scanResults.length} scan results for anomalies...`
    );

    // Count SSL certificate errors
    const sslErrors = scanResults.filter(
      (result) =>
        result.description?.includes("certificate has expired") ||
        result.description?.includes("CERTIFICATE_VERIFY_FAILED") ||
        result.description?.includes("SSL: CERTIFICATE_VERIFY_FAILED") ||
        (result.name?.toLowerCase().includes("ssl") &&
          result.description?.includes("expired"))
    );

    if (sslErrors.length > 0) {
      console.log(`Found ${sslErrors.length} SSL certificate errors`);
      anomalies.push({
        id: `ssl-expired-${Date.now()}`,
        component: "SSL Certificate",
        description: `SSL certificate has expired, causing ${sslErrors.length} connection failures across scan types`,
        severity: "high",
        recommendation:
          "Renew the SSL certificate immediately to restore secure HTTPS connections. This is preventing all secure scans from completing.",
        score: 1.0,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          affected_scans: sslErrors
            .map((e) => e.category || e.scan_type)
            .filter(Boolean),
          error_count: sslErrors.length,
        },
      });
    }

    // Count connection timeouts
    const timeouts = scanResults.filter(
      (result) =>
        result.description?.includes("SoftTimeLimitExceeded") ||
        result.description?.includes("timeout") ||
        result.description?.includes("TimeoutError")
    );

    if (timeouts.length > 0) {
      console.log(`Found ${timeouts.length} timeout errors`);
      anomalies.push({
        id: `timeout-${Date.now()}`,
        component: "Performance",
        description: `Scan timeouts detected (${timeouts.length} operations timed out)`,
        severity: "medium",
        recommendation:
          "Investigate server performance issues and optimize response times. Consider increasing timeout limits if server is legitimately slow.",
        score: 0.7,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          timeout_count: timeouts.length,
          affected_types: timeouts
            .map((t) => t.category || t.scan_type)
            .filter(Boolean),
        },
      });
    }

    // Check for widespread connection failures
    const connectionFailures = scanResults.filter(
      (result) =>
        result.description?.includes("Failed to connect") ||
        result.description?.includes("Max retries exceeded") ||
        result.description?.includes("Connection refused") ||
        result.description?.includes("Connection error")
    );

    if (connectionFailures.length > 3) {
      console.log(`Found ${connectionFailures.length} connection failures`);
      anomalies.push({
        id: `connection-failures-${Date.now()}`,
        component: "Website Availability",
        description: `Multiple connection failures detected (${connectionFailures.length} failed attempts)`,
        severity: "high",
        recommendation:
          "Check server availability, DNS resolution, and network connectivity. The website may be down or blocking scan requests.",
        score: 0.9,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          failure_count: connectionFailures.length,
          failure_types: connectionFailures
            .map((f) => f.category || f.scan_type)
            .filter(Boolean),
        },
      });
    }

    // Check for CORS configuration issues (many failed CORS checks)
    const corsErrors = scanResults.filter(
      (result) =>
        result.category === "cors" ||
        (result.description?.includes("CORS") &&
          result.description?.includes("Failed"))
    );

    if (corsErrors.length > 10) {
      console.log(`Found ${corsErrors.length} CORS-related errors`);
      anomalies.push({
        id: `cors-issues-${Date.now()}`,
        component: "CORS Configuration",
        description: `Unable to analyze CORS on ${corsErrors.length} endpoints due to connection issues`,
        severity: "medium",
        recommendation:
          "Fix underlying connection issues to properly assess CORS security configuration.",
        score: 0.6,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          cors_errors: corsErrors.length,
        },
      });
    }

    // Check for security header analysis failures
    const headerErrors = scanResults.filter(
      (result) =>
        result.category === "headers" &&
        result.description?.includes("Failed to connect")
    );

    if (headerErrors.length > 0) {
      anomalies.push({
        id: `header-analysis-failed-${Date.now()}`,
        component: "Security Headers",
        description:
          "Unable to analyze security headers due to connection failures",
        severity: "medium",
        recommendation:
          "Resolve connection issues to perform security header analysis",
        score: 0.5,
        is_false_positive: false,
        created_at: new Date().toISOString(),
      });
    }

    // Detect if website is completely unreachable
    const totalScans = scanResults.length;
    const totalErrors =
      connectionFailures.length + sslErrors.length + timeouts.length;

    if (totalErrors > totalScans * 0.8) {
      // 80% of scans failed
      anomalies.push({
        id: `website-unreachable-${Date.now()}`,
        component: "Website Status",
        description: `Website appears to be unreachable or heavily impaired (${Math.round(
          (totalErrors / totalScans) * 100
        )}% of scans failed)`,
        severity: "critical",
        recommendation:
          "Immediate investigation required: website may be down, DNS issues, or severe network problems",
        score: 1.0,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          total_scans: totalScans,
          failed_scans: totalErrors,
          failure_rate: Math.round((totalErrors / totalScans) * 100),
        },
      });
    }

    console.log(`Detected ${anomalies.length} connection-based anomalies`);
    return anomalies;
  },

  getAnomalyStats: async () => {
    try {
      const response = await api.get("/ai-analyzer/anomalies/stats/");
      console.log("Get anomaly stats response:", response); // Debug log

      return { success: true, data: response.data };
    } catch (error) {
      console.error("Error in getAnomalyStats:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.response?.data ||
          error.message ||
          "Unknown error",
      };
    }
  },

  markAsFalsePositive: async (anomalyId) => {
    // Validate anomalyId before making API call
    if (!anomalyId || anomalyId === "undefined") {
      console.error(
        "Invalid anomalyId provided to markAsFalsePositive:",
        anomalyId
      );
      return { success: false, error: "Invalid anomaly ID" };
    }

    try {
      const response = await api.post(
        `/ai-analyzer/anomalies/${anomalyId}/false_positive/`
      );
      console.log("Mark as false positive response:", response); // Debug log

      return { success: true, data: response.data };
    } catch (error) {
      console.error("Error in markAsFalsePositive:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.response?.data ||
          error.message ||
          "Unknown error",
      };
    }
  },

  /**
   * Detect anomalies in scan data using AI
   * @param {Object} scanData - The scan data to analyze
   * @returns {Promise<Object>} Response with detected anomalies
   */
  detectAnomalies: async (scanData) => {
    try {
      if (!anomalyService.validateAnomalyData(scanData)) {
        return {
          success: false,
          error: "Invalid scan data provided for anomaly detection",
        };
      }

      const response = await api.post(
        "/ai-analyzer/anomaly-detection/",
        scanData
      );
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      console.error("Error detecting anomalies:", error);
      return {
        success: false,
        error:
          error.response?.data?.error ||
          error.response?.data?.detail ||
          error.message ||
          "Failed to detect anomalies",
      };
    }
  },

  /**
   * Get historical anomaly data
   * @param {string} period - Time period (7d, 30d, 90d)
   * @returns {Promise<Object>} Historical anomaly data
   */
  getAnomalyHistory: async (period = "30d") => {
    try {
      const response = await api.get(
        `/ai-analyzer/anomaly-history/?period=${period}`
      );
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      console.error("Error fetching anomaly history:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to fetch anomaly history",
      };
    }
  },

  /**
   * Analyze security trends using historical data
   * @param {Array} historicalData - Historical scan data
   * @returns {Promise<Object>} Trend analysis results
   */
  analyzeSecurityTrends: async (historicalData) => {
    try {
      const response = await api.post("/ai-analyzer/trend-analysis/", {
        data: historicalData,
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      console.error("Error analyzing security trends:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to analyze security trends",
      };
    }
  },

  /**
   * Generate comprehensive anomaly report
   * @param {string} scanId - The scan ID to generate report for
   * @returns {Promise<Object>} Anomaly report
   */
  generateAnomalyReport: async (scanId) => {
    try {
      const response = await api.post("/ai-analyzer/anomaly-report/", {
        scan_id: scanId,
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      console.error("Error generating anomaly report:", error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          error.message ||
          "Failed to generate anomaly report",
      };
    }
  },

  /**
   * Validate anomaly detection input data
   * @param {Object} data - Data to validate
   * @returns {boolean} Whether data is valid
   */
  validateAnomalyData: (data) => {
    if (!data || typeof data !== "object") {
      return false;
    }

    // Check for required fields
    if (!data.target_url || typeof data.target_url !== "string") {
      return false;
    }

    if (!data.results || !Array.isArray(data.results)) {
      return false;
    }

    return true;
  },

  /**
   * Calculate anomaly score based on detected anomalies
   * @param {Array} anomalies - Array of detected anomalies
   * @returns {number} Anomaly risk score (0-100)
   */
  calculateAnomalyScore: (anomalies) => {
    if (!Array.isArray(anomalies) || anomalies.length === 0) {
      return 0;
    }

    const severityWeights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
      info: 1,
    };

    let totalScore = 0;
    let maxPossibleScore = 0;

    anomalies.forEach((anomaly) => {
      const severity = anomaly.severity?.toLowerCase() || "low";
      const confidence = anomaly.score || anomaly.confidence || 0.5;
      const weight = severityWeights[severity] || severityWeights.low;

      totalScore += weight * confidence;
      maxPossibleScore += weight;
    });

    // Normalize to 0-100 scale
    if (maxPossibleScore === 0) return 0;

    const normalizedScore = (totalScore / maxPossibleScore) * 100;
    return Math.min(100, Math.round(normalizedScore));
  },
};

// Export both as named export and default export to ensure compatibility
export { anomalyService };
export default anomalyService;
