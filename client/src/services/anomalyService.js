// src/services/anomalyService.js

import api from "./api";

// Create the service object with all required methods
const anomalyService = {
  // Existing methods
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

      return { success: true, data: anomaliesData };
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

  // New methods required by the test
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
      critical: 15,
      high: 8,
      medium: 4,
      low: 1,
      info: 0,
    };

    let totalScore = 0;
    let maxPossibleScore = 0;

    anomalies.forEach((anomaly) => {
      const severity = anomaly.severity?.toLowerCase() || "low";
      const confidence = anomaly.confidence || 0.5;
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
