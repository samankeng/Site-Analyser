// frontend/src/services/scanReportService.js

import api from "./api";
import { scanService } from "./scanService";

/**
 * Service to handle the integration between scans and reports
 */
export const scanReportService = {
  /**
   * Create a report from a completed scan
   * @param {string} scanId - The ID of the completed scan
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  createReportFromScan: async (scanId) => {
    try {
      // First check if the scan is completed
      const scanResponse = await scanService.getScan(scanId);

      if (!scanResponse.success) {
        return {
          success: false,
          error: "Failed to fetch scan details.",
        };
      }

      if (scanResponse.data.status !== "completed") {
        return {
          success: false,
          error: "Cannot create a report from an incomplete scan.",
        };
      }

      // Try to create a report from the scan
      const response = await api.post(
        `/scanner/scans/${scanId}/create-report/`
      );
      return { success: true, data: response.data };
    } catch (error) {
      console.error(`Error creating report from scan ${scanId}:`, error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          "Failed to create report from scan. Please try again.",
      };
    }
  },

  /**
   * Get the associated report for a scan (if exists)
   * @param {string} scanId - The ID of the scan
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportForScan: async (scanId) => {
    try {
      const response = await api.get(`/scanner/scans/${scanId}/report/`);
      return { success: true, data: response.data };
    } catch (error) {
      // A 404 is expected if no report exists yet
      if (error.response && error.response.status === 404) {
        return { success: false, data: null };
      }

      console.error(`Error fetching report for scan ${scanId}:`, error);
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          "Failed to fetch report for scan. Please try again.",
      };
    }
  },

  /**
   * Ensure that all completed scans have associated reports
   * This can be called on dashboard or reports page load to sync any missing reports
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  syncCompletedScansToReports: async () => {
    try {
      // First, get all scans
      const scansResponse = await scanService.getScans();

      if (!scansResponse.success) {
        return { success: false, error: "Failed to fetch scans for sync." };
      }

      // Extract scans array, handling different response formats
      let scans = [];
      if (Array.isArray(scansResponse.data)) {
        scans = scansResponse.data;
      } else if (
        scansResponse.data &&
        Array.isArray(scansResponse.data.results)
      ) {
        scans = scansResponse.data.results;
      }

      // Filter to completed scans only
      const completedScans = scans.filter(
        (scan) => scan.status === "completed"
      );

      // For each completed scan, ensure it has a report
      let createdReports = 0;
      let errors = [];

      for (const scan of completedScans) {
        // Check if report already exists
        const reportResponse = await scanReportService.getReportForScan(
          scan.id
        );

        // If no report exists, create one
        if (!reportResponse.success || !reportResponse.data) {
          const createResponse = await scanReportService.createReportFromScan(
            scan.id
          );
          if (createResponse.success) {
            createdReports++;
          } else {
            errors.push(
              `Failed to create report for scan ${scan.id}: ${createResponse.error}`
            );
          }
        }
      }

      return {
        success: true,
        data: {
          message: `Sync complete. Created ${createdReports} new reports.`,
          createdCount: createdReports,
          errors: errors,
        },
      };
    } catch (error) {
      console.error("Error syncing scans to reports:", error);
      return {
        success: false,
        error: "Failed to sync scans to reports. Please try again.",
      };
    }
  },
};

export default scanReportService;
