// frontend/src/services/reportService.js - Updated to use only PDF reports

import {
  calculateSecurityScore,
  countCategories,
  countSeverities,
  getHighestSeverity,
} from "../utils/securityUtils";
import api from "./api";
import { scanService } from "./scanService";

/**
 * Service that handles PDF report functionality from scans
 */
export const reportService = {
  /**
   * Get all reports (generated from scans)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReports: async () => {
    return reportService.getVirtualReports();
  },

  /**
   * Get all reports (converted from scans)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getVirtualReports: async () => {
    try {
      // Fetch all scans
      const scansResponse = await scanService.getScans();

      if (!scansResponse.success) {
        return {
          success: false,
          error: scansResponse.error || "Failed to fetch scans.",
        };
      }

      // Extract scans array from response
      let scans = [];
      if (Array.isArray(scansResponse.data)) {
        scans = scansResponse.data;
      } else if (
        scansResponse.data &&
        Array.isArray(scansResponse.data.results)
      ) {
        scans = scansResponse.data.results;
      }

      // For each scan, get complete results for better reporting
      const reportsPromises = scans.map(async (scan) => {
        // For completed scans, fetch detailed results
        if (
          scan.status === "completed" &&
          (!scan.results || scan.results.length === 0)
        ) {
          try {
            const resultsResponse = await scanService.getScanResults(scan.id);
            if (resultsResponse.success) {
              // Merge scan with results
              return reportService.convertScanToReport({
                ...scan,
                results: resultsResponse.data.results || [],
              });
            }
          } catch (e) {
            console.error(`Error fetching results for scan ${scan.id}:`, e);
          }
        }

        // Fallback to basic conversion if results fetch fails or not needed
        return reportService.convertScanToReport(scan);
      });

      const reports = await Promise.all(reportsPromises);
      return { success: true, data: reports };
    } catch (error) {
      console.error("Error getting virtual reports:", error);
      return {
        success: false,
        error: "Failed to generate reports from scans. Please try again.",
      };
    }
  },

  /**
   * Get a single report by ID (converted from a scan)
   * @param {string} reportId - The ID of the report (same as scan ID)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportById: async (reportId) => {
    try {
      // Use scanService.getScanWithResults for complete data in one request
      const scanResponse = await scanService.getScanWithResults(reportId);

      if (!scanResponse.success) {
        return {
          success: false,
          error: scanResponse.error || "Failed to fetch scan details.",
        };
      }

      // Convert the scan to a report format
      const report = reportService.convertScanToReport(scanResponse.data);

      return { success: true, data: report };
    } catch (error) {
      console.error(`Error getting virtual report ${reportId}:`, error);
      return {
        success: false,
        error: "Failed to generate report from scan. Please try again.",
      };
    }
  },

  /**
   * Convert a scan object to a report format
   * @param {Object} scan - Scan object from API
   * @returns {Object} Report-formatted object
   */
  convertScanToReport: (scan) => {
    // Use standardized security utilities to calculate metrics
    const results = scan.results || [];

    // Count findings by severity
    const findingCounts = countSeverities(results);

    // Count findings by category
    const categoryResults = countCategories(results);

    // Determine highest severity
    const highestSeverity = getHighestSeverity(findingCounts);

    // Calculate category scores
    const categoryScores = {
      headers: 100,
      ssl: 100,
      vulnerabilities: 100,
      content: 100,
    };

    const securityScore =
      scan.security_score !== undefined
        ? scan.security_score
        : calculateSecurityScore(results); // Fall back to calculation

    // Group results by category
    const resultsByCategory = {};
    (scan.results || []).forEach((result) => {
      const category = result.category?.toLowerCase() || "unknown";
      if (!resultsByCategory[category]) {
        resultsByCategory[category] = [];
      }
      resultsByCategory[category].push(result);
    });

    // Calculate score for each category
    const severityWeights = {
      critical: 15,
      high: 8,
      medium: 4,
      low: 1,
      info: 0,
    };

    Object.entries(resultsByCategory).forEach(([category, results]) => {
      if (category in categoryScores) {
        let deduction = 0;
        results.forEach((result) => {
          deduction +=
            severityWeights[result.severity?.toLowerCase() || "info"] || 0;
        });
        categoryScores[category] = Math.max(0, Math.min(100, 100 - deduction));
      }
    });

    // Create a virtual report object from the scan
    return {
      id: scan.id,
      scan_id: scan.id, // Reference to original scan
      user: scan.user,
      name: scan.name || `Report for ${scan.target_url}`,
      target_url: scan.target_url,
      status: scan.status,
      status_display:
        scan.status.charAt(0).toUpperCase() + scan.status.slice(1), // Capitalize for display
      created_at: scan.created_at,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      scan_types: scan.scan_types || [],
      highest_severity: highestSeverity,
      highest_severity_display:
        highestSeverity.charAt(0).toUpperCase() + highestSeverity.slice(1),
      security_score: securityScore,
      category_scores: categoryScores,
      findings_summary: {
        counts: findingCounts,
        total: Object.values(findingCounts).reduce((a, b) => a + b, 0),
      },
      category_counts: categoryResults,
      // Include the original scan results for reference
      results: results,
      is_virtual: true, // Flag to indicate this is a virtual report
    };
  },

  /**
   * Generate a PDF report for a single scan
   * @param {string} scanId - The ID of the scan
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  generatePdf: async (scanId) => {
    try {
      const response = await api.get(`scanner/scans/${scanId}/pdf_report/`, {
        responseType: "blob",
      });

      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers["content-disposition"];
      let filename = `security-report-${scanId}.pdf`;

      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch && filenameMatch.length > 1) {
          filename = filenameMatch[1];
        }
      }

      // Create a download link
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();

      // Clean up
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);

      return { success: true };
    } catch (error) {
      console.error(`Error generating PDF for scan ${scanId}:`, error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          "Failed to generate PDF report. Please try again.",
      };
    }
  },

  /**
   * Export multiple scans as PDF reports
   * @param {Array<string>} scanIds - Array of scan IDs to export
   * @param {string} format - Export format (only 'pdf' supported)
   * @param {Object} options - Additional export options (ignored for PDF)
   */
  exportReports: async (scanIds, format = "pdf", options = {}) => {
    try {
      if (format !== "pdf") {
        alert(
          `Export format "${format}" is not supported. Only PDF is available.`
        );
        return {
          success: false,
          error: `Export format "${format}" is not supported.`,
        };
      }

      // For multiple reports, download them one by one
      if (scanIds.length === 1) {
        return await reportService.generatePdf(scanIds[0]);
      }

      // For multiple reports, inform user and download the first one
      const result = await reportService.generatePdf(scanIds[0]);
      if (result.success && scanIds.length > 1) {
        alert(
          `Downloaded 1 of ${scanIds.length} reports. Multiple report export downloads each report individually.`
        );

        // Optionally download all reports with a delay
        for (let i = 1; i < scanIds.length; i++) {
          setTimeout(() => {
            reportService.generatePdf(scanIds[i]);
          }, i * 1000); // 1 second delay between downloads
        }
      }
      return result;
    } catch (error) {
      console.error("Error exporting reports:", error);
      return {
        success: false,
        error: "Failed to export reports. Please try again.",
      };
    }
  },
};

export default reportService;
