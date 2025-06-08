// frontend/src/services/scanService.js - Updated to remove database report methods

import { processScanResults } from "../models/ScanResultsModel";
import {
  calculateSecurityScore,
  getSecurityRating,
} from "../utils/securityUtils";
import api from "./api";

export const scanService = {
  // ========== SCAN METHODS ==========

  // Get all scans for current user
  getScans: async (page = 1) => {
    try {
      const response = await api.get(`/scanner/scans/?page=${page}`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Get a specific scan
  getScan: async (id) => {
    try {
      const response = await api.get(`/scanner/scans/${id}/`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Create a new scan (Enhanced with scan mode support)
  createScan: async (scanData) => {
    try {
      const payload = {
        target_url: scanData.target_url,
        scan_types: scanData.scan_types || [],
        scan_mode: scanData.scan_mode || "passive",
        compliance_mode: scanData.compliance_mode || "strict",
      };

      const response = await api.post("/scanner/scans/", payload);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Cancel a scan
  cancelScan: async (id) => {
    try {
      const response = await api.post(`/scanner/scans/${id}/cancel/`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Delete a specific scan
  deleteScan: async (id) => {
    try {
      const response = await api.delete(`/scanner/scans/${id}/`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Delete all scan history for the current user
  deleteScanHistory: async () => {
    try {
      const response = await api.delete("/scanner/scans/history/");
      return { success: true, data: response.data };
    } catch (error) {
      console.error("Error deleting scan history:", error);
      return {
        success: false,
        error: error.response?.data || "Failed to delete scan history",
      };
    }
  },

  // Get scan results
  getScanResults: async (scanId) => {
    try {
      let allResults = [];
      let page = 1;
      let hasNext = true;

      while (hasNext) {
        const response = await api.get(
          `/scanner/scans/${scanId}/results/?page=${page}`
        );
        const data = response.data;

        const results = Array.isArray(data.results) ? data.results : data;
        allResults = allResults.concat(results);
        hasNext = !!data.next;
        page++;
      }

      return { success: true, data: { results: allResults } };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Combine scan data and results
  getScanWithResults: async (id) => {
    try {
      const scanResponse = await api.get(`/scanner/scans/${id}/`);

      // Fetch ALL paginated results
      let allResults = [];
      let page = 1;
      let hasNext = true;

      while (hasNext) {
        const response = await api.get(
          `/scanner/scans/${id}/results/?page=${page}`
        );
        const data = response.data;

        const results = Array.isArray(data.results) ? data.results : data;
        allResults = allResults.concat(results);
        hasNext = !!data.next;
        page++;
      }

      const processedData = processScanResults(scanResponse.data, allResults);

      return { success: true, data: processedData };
    } catch (error) {
      console.error("Error fetching scan with results:", error);
      return { success: false, error: error.response?.data };
    }
  },

  // Download scan report as PDF
  downloadScanReport: async (scanId) => {
    try {
      const response = await api.get(`/scanner/scans/${scanId}/pdf_report/`, {
        responseType: "blob",
      });

      // Create a download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;

      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers["content-disposition"];
      let filename = `security-scan-${scanId}.pdf`;
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch && filenameMatch.length > 1) {
          filename = filenameMatch[1];
        }
      }

      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();

      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);

      return { success: true };
    } catch (error) {
      console.error("Error downloading report:", error);
      return {
        success: false,
        error: error.response?.data || "Failed to download report",
      };
    }
  },

  // ========== COMPLIANCE METHODS (UPDATED ENDPOINTS) ==========

  // Get user's compliance status
  getComplianceStatus: async () => {
    try {
      const response = await api.get("/compliance/status/");
      return response.data;
    } catch (error) {
      console.error("Failed to fetch compliance status:", error);
      // Return fallback status that allows passive scanning
      return {
        all_agreements_accepted: false,
        missing_agreements: [
          "terms_of_service",
          "privacy_policy",
          "responsible_disclosure",
        ],
        agreements: {
          terms_of_service: false,
          privacy_policy: false,
          responsible_disclosure: false,
          active_scanning: false,
        },
        can_active_scan: false,
        authorized_domains: [],
        scan_capabilities: {
          passive_enabled: false,
          active_enabled: false,
          mixed_enabled: false,
          note: "Error loading compliance status",
        },
      };
    }
  },

  // Get available scan modes
  getScanModes: async () => {
    try {
      const response = await api.get("/compliance/scan-modes/");
      return response.data;
    } catch (error) {
      console.error("Failed to fetch scan modes:", error);
      // Return fallback scan modes
      return {
        passive: {
          name: "Passive Scan",
          description:
            "Safe, non-intrusive scanning that can be performed on any website",
          legal_risk: "Very Low",
          authorization_required: false,
          requirements: [
            "Accept Terms of Service",
            "Accept Privacy Policy",
            "Accept Responsible Disclosure Agreement",
          ],
        },
        active: {
          name: "Active Scan",
          description:
            "Intrusive testing that may trigger security alerts - requires domain authorization",
          legal_risk: "High",
          authorization_required: true,
          requirements: [
            "Accept all legal agreements",
            "Accept Active Scanning Agreement",
            "Verify domain ownership OR target pre-authorized test domains",
          ],
        },
        mixed: {
          name: "Mixed Scan",
          description:
            "Combines passive and active testing with intelligent authorization checks",
          legal_risk: "Medium",
          authorization_required: true,
          requirements: [
            "Accept all legal agreements",
            "Accept Active Scanning Agreement",
            "Verify domain ownership OR target pre-authorized test domains",
          ],
        },
      };
    }
  },

  // Accept a legal agreement
  acceptAgreement: async (agreementType) => {
    try {
      const response = await api.post("/compliance/accept/", {
        agreement_type: agreementType,
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || {
          message: "Failed to accept agreement",
        },
      };
    }
  },

  // ========== DOMAIN AUTHORIZATION METHODS (UPDATED ENDPOINTS) ==========

  // Check what scan modes are available for a specific URL
  checkUrlAuthorization: async (url) => {
    try {
      const response = await api.post("/compliance/check-url/", { url });
      return response.data;
    } catch (error) {
      console.error("Error checking URL authorization:", error);
      return {
        url: url,
        domain: new URL(url).hostname,
        scan_capabilities: {
          passive_enabled: true,
          active_enabled: false,
          mixed_enabled: false,
          reason: "Error checking authorization",
        },
      };
    }
  },

  // Request domain authorization
  requestDomainAuth: async (domain, method = "dns_txt") => {
    try {
      const response = await api.post("/compliance/request-domain/", {
        domain,
        verification_method: method,
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || {
          message: "Failed to request domain authorization",
        },
      };
    }
  },

  // Verify domain authorization
  verifyDomainAuth: async (domainId) => {
    try {
      const response = await api.post("/compliance/verify-domain/", {
        domain_id: domainId,
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || {
          message: "Failed to verify domain authorization",
        },
      };
    }
  },

  // Get user's domain authorizations
  getDomainAuthorizations: async () => {
    try {
      const response = await api.get("/compliance/domains/");
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || {
          message: "Failed to fetch domain authorizations",
        },
      };
    }
  },

  // ========== LEGACY COMPLIANCE METHODS (Keep for backward compatibility) ==========

  // Get compliance report for a scan
  getComplianceReport: async (scanId) => {
    try {
      const response = await api.get(
        `/scanner/scans/${scanId}/compliance_report/`
      );
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || {
          message: "Failed to fetch compliance report",
        },
      };
    }
  },

  // Get legal notices
  getLegalNotices: async () => {
    try {
      const response = await api.get("/compliance/legal-notices/");
      return response.data;
    } catch (error) {
      console.error("Failed to fetch legal notices:", error);
      return {
        terms_of_service: {
          title: "Terms of Service",
          content:
            "Please accept our terms of service to use the scanning service.",
          version: "1.0",
        },
        privacy_policy: {
          title: "Privacy Policy",
          content: "Please review our privacy policy.",
          version: "1.0",
        },
        responsible_disclosure: {
          title: "Responsible Disclosure Guidelines",
          content: "Please follow responsible disclosure practices.",
          version: "1.0",
        },
        active_scanning_notice: {
          title: "Active Scanning Legal Notice",
          content:
            "Active scanning requires explicit authorization and may be illegal without proper consent.",
          version: "1.0",
          required_for: ["active", "mixed"],
        },
      };
    }
  },

  // ========== UTILITY METHODS ==========

  // Check if a domain requires authorization for active scanning
  checkDomainAuthorization: async (domain, scanMode = "passive") => {
    try {
      // Development domains that don't require authorization
      const developmentDomains = [
        "badssl.com",
        "testphp.vulnweb.com",
        "demo.testfire.net",
        "httpbin.org",
        "localhost",
        "127.0.0.1",
        "reqbin.com",
      ];

      const isDevelopmentDomain = developmentDomains.some((devDomain) =>
        domain.includes(devDomain)
      );

      if (scanMode === "passive" || isDevelopmentDomain) {
        return {
          required: false,
          reason:
            scanMode === "passive"
              ? "Passive scanning does not require authorization"
              : "Pre-authorized test domain",
        };
      }

      // For active/mixed scans, check via the API
      const authResponse = await this.checkUrlAuthorization(
        `https://${domain}`
      );

      return {
        required: true,
        authorized: authResponse.scan_capabilities?.active_enabled || false,
        reason:
          authResponse.scan_capabilities?.reason ||
          "Domain authorization required",
      };
    } catch (error) {
      console.error("Error checking domain authorization:", error);
      return {
        required: true,
        authorized: false,
        error: "Failed to check authorization",
      };
    }
  },

  // Validate scan configuration before submission
  validateScanConfig: async (scanConfig) => {
    const errors = [];

    // Validate URL
    if (!scanConfig.target_url) {
      errors.push("Target URL is required");
    } else {
      try {
        new URL(scanConfig.target_url);
      } catch {
        errors.push("Invalid URL format");
      }
    }

    // Validate scan types
    if (!scanConfig.scan_types || scanConfig.scan_types.length === 0) {
      errors.push("At least one scan type must be selected");
    }

    // Validate scan mode
    const validModes = ["passive", "active", "mixed"];
    if (!validModes.includes(scanConfig.scan_mode || "passive")) {
      errors.push("Invalid scan mode");
    }

    // Check authorization for active/mixed scans
    if (
      scanConfig.scan_mode &&
      ["active", "mixed"].includes(scanConfig.scan_mode)
    ) {
      try {
        const authCheck = await this.checkUrlAuthorization(
          scanConfig.target_url
        );

        if (!authCheck.scan_capabilities?.active_enabled) {
          errors.push(
            `${
              scanConfig.scan_mode.charAt(0).toUpperCase() +
              scanConfig.scan_mode.slice(1)
            } scanning requires domain authorization: ${
              authCheck.scan_capabilities?.reason || "Authorization required"
            }`
          );
        }
      } catch (error) {
        errors.push("Failed to validate domain authorization");
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  },

  // Calculate security score based on scan results
  calculateSecurityScore,

  // Get risk level text based on security score
  getRiskLevelText: getSecurityRating,
};

export default scanService;
