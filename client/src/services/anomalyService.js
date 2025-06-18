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

      // ENHANCED: Handle different anomaly data formats
      let anomaliesData = response.data;

      // Check if the response is an object with a results or items property containing the anomalies
      if (!Array.isArray(anomaliesData) && typeof anomaliesData === "object") {
        if (Array.isArray(anomaliesData.results)) {
          anomaliesData = anomaliesData.results;
        } else if (Array.isArray(anomaliesData.items)) {
          anomaliesData = anomaliesData.items;
        } else if (Array.isArray(anomaliesData.anomalies)) {
          // FIXED: Handle backend anomaly format
          anomaliesData = anomaliesData.anomalies;
        } else if (anomaliesData.is_anomaly && anomaliesData.anomalies) {
          // FIXED: Handle enhanced anomaly detection response format
          anomaliesData = anomaliesData.anomalies;
          console.log(
            `Backend detected ${anomaliesData.length} anomalies with score ${
              anomaliesData.anomaly_score || 0
            }`
          );
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

      // ENHANCED: Transform backend anomaly format to frontend format
      if (Array.isArray(anomaliesData)) {
        anomaliesData = anomaliesData.map((anomaly, index) => {
          // If it's already in the correct format, keep it
          if (anomaly.component && anomaly.id) {
            return anomaly;
          }

          // Transform backend format to frontend format
          return {
            id: anomaly.id || `backend-anomaly-${index}-${Date.now()}`,
            component: anomalyService.getComponentFromType(
              anomaly.type || "unknown"
            ),
            severity: anomaly.severity || "medium",
            description: anomaly.description || "No description available",
            recommendation: anomaly.recommendation || null,
            score: anomaly.anomaly_score || anomaly.score || 0.5,
            is_false_positive: false,
            created_at: anomaly.created_at || new Date().toISOString(),
            details: anomaly.details || {},
            type: anomaly.type || "unknown", // Keep original type for debugging
            affected_items: anomaly.affected_items || 0,
          };
        });
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

      // Apply smart prioritization (keeping your existing logic)
      if (anomaliesData && anomaliesData.length > 0) {
        // Smart prioritization algorithm
        const prioritized = anomaliesData.map((anomaly) => {
          // Priority scoring weights
          const severityWeights = {
            critical: 15,
            high: 8,
            medium: 4,
            low: 0.5,
            info: 0,
          };
          const componentWeights = {
            "SSL Certificate": 9,
            "Website Status": 9,
            "Website Availability": 9,
            "Security Headers": 8,
            "Environment Security": 8,
            "Issue Concentration Analysis": 7, // NEW
            "Issue Volume Analysis": 6, // NEW
            "Content Security": 6, // NEW
            Performance: 6,
            "CORS Configuration": 5,
            "Security Monitoring": 4,
          };

          const severityWeight = severityWeights[anomaly.severity] || 1;
          const componentWeight = componentWeights[anomaly.component] || 3;
          const confidenceScore = anomaly.score || 0.5;

          const priorityScore =
            severityWeight * componentWeight * confidenceScore;

          return {
            ...anomaly,
            priority_score: priorityScore,
            priority_level:
              priorityScore > 40
                ? "immediate"
                : priorityScore > 20
                ? "high"
                : priorityScore > 10
                ? "medium"
                : "low",
          };
        });

        // Sort by priority (highest first)
        anomaliesData = prioritized.sort(
          (a, b) => b.priority_score - a.priority_score
        );

        console.log(
          `Applied smart prioritization to ${anomaliesData.length} anomalies`
        );
        console.log(
          `Immediate action required: ${
            anomaliesData.filter((a) => a.priority_level === "immediate").length
          }`
        );
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

  getComponentFromType: (type) => {
    const typeToComponentMap = {
      missing_security_headers: "Security Headers",
      critical_security_headers_missing: "Critical Security Headers",
      ssl_configuration_issues: "SSL/TLS Configuration",
      medium_severity_concentration: "Issue Concentration Analysis",
      high_severity_concentration: "High Severity Issues",
      excessive_issue_count: "Issue Volume Analysis",
      vulnerability_cluster: "Vulnerability Clustering",
      critical_vulnerability_cluster: "Critical Vulnerabilities",
      performance_degradation: "Performance Analysis",
      connection_timeouts: "Connection Issues",
      ssl_test_site_patterns: "SSL Test Site Detection",
      content_security_issues: "Content Security",
      scan_failure_anomalies: "Scan Quality",
      unknown: "General Analysis",
    };

    return typeToComponentMap[type] || "General Analysis";
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

  // Add this new method (doesn't change existing ones)
  startRealTimeMonitoring: (scanId, onUpdate) => {
    if (!scanId || scanId === "undefined") {
      console.error("Invalid scanId for real-time monitoring:", scanId);
      return null;
    }

    console.log(`Starting real-time anomaly monitoring for scan ${scanId}`);

    let attempts = 0;
    const maxAttempts = 30; // 5 minutes

    const monitoringInterval = setInterval(async () => {
      attempts++;

      try {
        // Check current scan status
        const statusResponse = await api.get(`/scanner/scans/${scanId}/`);
        const status = statusResponse.data.status;

        console.log(`Real-time monitor attempt ${attempts}: ${status}`);

        // Get current anomalies
        const anomalyResponse = await anomalyService.getAnomaliesForScan(
          scanId
        );

        if (anomalyResponse.success && anomalyResponse.data.length > 0) {
          // Filter for new high-priority anomalies
          const urgentAnomalies = anomalyResponse.data.filter(
            (a) =>
              a.priority_level === "immediate" ||
              a.severity === "critical" ||
              a.severity === "high"
          );

          if (urgentAnomalies.length > 0) {
            console.log(
              `Real-time: Found ${urgentAnomalies.length} urgent anomalies`
            );
            onUpdate({
              type: "urgent_anomalies",
              anomalies: urgentAnomalies,
              scan_status: status,
              timestamp: new Date().toISOString(),
            });
          }
        }

        // Stop monitoring when scan completes
        if (status === "completed" || status === "failed") {
          clearInterval(monitoringInterval);
          console.log(`Real-time monitoring stopped: scan ${status}`);

          // Final anomaly check
          const finalCheck = await anomalyService.getAnomaliesForScan(scanId);
          onUpdate({
            type: "final_report",
            anomalies: finalCheck.success ? finalCheck.data : [],
            scan_status: status,
            timestamp: new Date().toISOString(),
          });

          return;
        }

        // Stop if max attempts reached
        if (attempts >= maxAttempts) {
          clearInterval(monitoringInterval);
          console.warn("Real-time monitoring timeout reached");
          onUpdate({
            type: "timeout",
            message: "Monitoring timeout after 5 minutes",
            timestamp: new Date().toISOString(),
          });
        }
      } catch (error) {
        console.error("Real-time monitoring error:", error);
        // Continue monitoring despite errors
      }
    }, 10000); // Check every 10 seconds

    return monitoringInterval; // Return interval ID so it can be cleared
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

    // YOUR EXISTING SSL CHECKS - enhanced
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

    // YOUR EXISTING TIMEOUT CHECKS - enhanced
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

    // YOUR EXISTING CONNECTION FAILURE CHECKS - enhanced
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

    // YOUR EXISTING CORS CHECKS - enhanced
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

    // YOUR EXISTING HEADER ERROR CHECKS - kept exactly the same
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

    // YOUR EXISTING UNREACHABLE WEBSITE CHECK - enhanced
    const totalScans = scanResults.length;
    const totalErrors =
      connectionFailures.length + sslErrors.length + timeouts.length;

    if (totalErrors > totalScans * 0.8) {
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

    // ADD NEW CHECKS WITHOUT CHANGING EXISTING STRUCTURE

    // Check for performance degradation patterns
    const perfResults = scanResults.filter(
      (r) =>
        r.category === "performance" || r.description?.includes("response time")
    );
    if (perfResults.length > 0) {
      const responseTimes = perfResults
        .map((r) => r.details?.response_time || r.response_time)
        .filter((t) => typeof t === "number" && t > 0);

      if (responseTimes.length > 0) {
        const avgResponseTime =
          responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
        const maxResponseTime = Math.max(...responseTimes);

        if (avgResponseTime > 3.0) {
          // Slow average response
          anomalies.push({
            id: `slow-performance-${Date.now()}`,
            component: "Performance",
            description: `Poor overall performance detected (avg: ${avgResponseTime.toFixed(
              2
            )}s, max: ${maxResponseTime.toFixed(2)}s)`,
            severity: avgResponseTime > 5.0 ? "high" : "medium",
            recommendation:
              "Optimize server performance, implement caching, or upgrade server resources",
            score: Math.min(1.0, avgResponseTime / 10),
            is_false_positive: false,
            created_at: new Date().toISOString(),
            details: {
              avg_response: avgResponseTime,
              max_response: maxResponseTime,
            },
          });
        }

        // Check for high variance in response times
        if (responseTimes.length > 1) {
          const mean = avgResponseTime;
          const variance =
            responseTimes.reduce(
              (acc, time) => acc + Math.pow(time - mean, 2),
              0
            ) / responseTimes.length;
          const stdDev = Math.sqrt(variance);

          if (stdDev > mean * 0.5) {
            // High variance
            anomalies.push({
              id: `inconsistent-performance-${Date.now()}`,
              component: "Performance Consistency",
              description: `Inconsistent response times detected (std dev: ${stdDev.toFixed(
                2
              )}s)`,
              severity: "medium",
              recommendation:
                "Investigate server load balancing and resource allocation inconsistencies",
              score: 0.6,
              is_false_positive: false,
              created_at: new Date().toISOString(),
              details: { std_deviation: stdDev, variance: variance },
            });
          }
        }
      }
    }

    // Check for security header clustering (many missing headers)
    const headerResults = scanResults.filter((r) => r.category === "headers");
    const criticalHeaderIssues = headerResults.filter(
      (h) => h.severity === "high" || h.severity === "critical"
    );

    if (criticalHeaderIssues.length > 5) {
      anomalies.push({
        id: `security-header-cluster-${Date.now()}`,
        component: "Security Headers",
        description: `Multiple critical security headers missing (${criticalHeaderIssues.length} issues)`,
        severity: "high",
        recommendation:
          "Implement comprehensive security header policy using web server configuration or middleware",
        score: 0.85,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          issue_count: criticalHeaderIssues.length,
          affected_headers: criticalHeaderIssues
            .map((h) => h.name)
            .slice(0, 10),
        },
      });
    }

    // Check for development environment indicators
    const devIndicators = scanResults.filter(
      (r) =>
        r.description?.toLowerCase().includes("debug") ||
        r.description?.toLowerCase().includes("development") ||
        r.description?.toLowerCase().includes("staging") ||
        r.description?.toLowerCase().includes("test")
    );

    if (devIndicators.length > 0) {
      anomalies.push({
        id: `dev-environment-${Date.now()}`,
        component: "Environment Security",
        description: `Development environment indicators detected (${devIndicators.length} instances)`,
        severity: "high",
        recommendation:
          "Remove debug information and development configurations from production",
        score: 0.9,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          indicator_count: devIndicators.length,
          indicators: devIndicators.map((d) => d.description).slice(0, 5),
        },
      });
    }

    // Check for potential scanning/attack patterns
    const errorPatterns = scanResults.filter(
      (r) =>
        r.description?.includes("404") ||
        r.description?.includes("403") ||
        r.description?.includes("500") ||
        r.description?.includes("error")
    );

    if (errorPatterns.length > 15) {
      // High number of errors might indicate scanning
      anomalies.push({
        id: `potential-scanning-${Date.now()}`,
        component: "Security Monitoring",
        description: `High error rate detected (${errorPatterns.length} errors), possible scanning activity`,
        severity: "medium",
        recommendation:
          "Monitor access logs for scanning attempts and consider implementing rate limiting",
        score: 0.6,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          error_count: errorPatterns.length,
          error_sample: errorPatterns.slice(0, 5).map((e) => e.description),
        },
      });
    }

    // Check for missing security scan categories
    const availableCategories = [
      ...new Set(scanResults.map((r) => r.category).filter(Boolean)),
    ];
    const expectedCategories = ["headers", "ssl", "cors", "cookies"];
    const missingCategories = expectedCategories.filter(
      (cat) => !availableCategories.includes(cat)
    );

    if (missingCategories.length > 0) {
      anomalies.push({
        id: `incomplete-security-scan-${Date.now()}`,
        component: "Scan Coverage",
        description: `Security scan incomplete: missing ${missingCategories.join(
          ", "
        )} analysis`,
        severity: "medium",
        recommendation:
          "Ensure all security scan modules are functioning properly",
        score: 0.5,
        is_false_positive: false,
        created_at: new Date().toISOString(),
        details: {
          missing_categories: missingCategories,
          available_categories: availableCategories,
        },
      });
    }

    console.log(
      `Detected ${anomalies.length} total anomalies (enhanced detection)`
    );
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
      critical: 15,
      high: 8,
      medium: 4,
      low: 0.5,
      info: 0,
    };

    let totalScore = 0;
    let maxPossibleScore = 0;
    let patternMultiplier = 1.0;

    // Detect anomaly patterns (ML-style)
    const severityCounts = anomalies.reduce((acc, anomaly) => {
      const severity = anomaly.severity?.toLowerCase() || "low";
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    }, {});

    const componentCounts = anomalies.reduce((acc, anomaly) => {
      const component = anomaly.component || "Unknown";
      acc[component] = (acc[component] || 0) + 1;
      return acc;
    }, {});

    // ML-style pattern detection
    // Pattern 1: Cascading failures (multiple components affected)
    if (Object.keys(componentCounts).length > 3) {
      patternMultiplier *= 1.3; // 30% increase for widespread issues
      console.log(
        "ML Pattern detected: Cascading failures across multiple components"
      );
    }

    // Pattern 2: Severity clustering (many high/critical issues)
    const highSeverityCount =
      (severityCounts.critical || 0) + (severityCounts.high || 0);
    if (highSeverityCount > anomalies.length * 0.6) {
      patternMultiplier *= 1.4; // 40% increase for severity clustering
      console.log("ML Pattern detected: High severity clustering");
    }

    // Pattern 3: Security infrastructure breakdown
    const securityComponents = [
      "SSL Certificate",
      "Security Headers",
      "CORS Configuration",
      "Website Status",
    ];
    const securityIssues = Object.keys(componentCounts).filter((comp) =>
      securityComponents.some((sec) => comp.includes(sec))
    ).length;

    if (securityIssues >= 3) {
      patternMultiplier *= 1.5; // 50% increase for security infrastructure issues
      console.log("ML Pattern detected: Security infrastructure breakdown");
    }

    // Pattern 4: Performance correlation (performance + availability issues)
    const hasPerformanceIssues = componentCounts["Performance"] > 0;
    const hasAvailabilityIssues =
      componentCounts["Website Availability"] > 0 ||
      componentCounts["Website Status"] > 0;

    if (hasPerformanceIssues && hasAvailabilityIssues) {
      patternMultiplier *= 1.2; // 20% increase for correlated issues
      console.log("ML Pattern detected: Performance-availability correlation");
    }

    anomalies.forEach((anomaly) => {
      const severity = anomaly.severity?.toLowerCase() || "low";
      const confidence = anomaly.score || anomaly.confidence || 0.5;
      const weight = severityWeights[severity] || severityWeights.low;

      totalScore += weight * confidence;
      maxPossibleScore += weight;
    });

    // Apply ML pattern multiplier
    totalScore *= patternMultiplier;
    maxPossibleScore *= patternMultiplier;

    // Normalize to 0-100 scale
    if (maxPossibleScore === 0) return 0;

    const normalizedScore = (totalScore / maxPossibleScore) * 100;
    const finalScore = Math.min(100, Math.round(normalizedScore));

    console.log(
      `ML-Enhanced Anomaly Score: ${finalScore}/100 (pattern multiplier: ${patternMultiplier.toFixed(
        2
      )})`
    );
    return finalScore;
  },
};

// Export both as named export and default export to ensure compatibility
export { anomalyService };
export default anomalyService;
