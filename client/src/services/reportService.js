// frontend/src/services/reportService.js

import api from './api';
import { scanService } from './scanService';
import { 
  calculateSecurityScore, 
  countSeverities, 
  countCategories,
  getHighestSeverity
} from '../utils/securityUtils';

/**
 * Unified service that handles all report functionality,
 * supporting both virtual reports (generated from scans) and real persisted reports
 */
export const reportService = {
  /**
   * Get all reports (virtual or real)
   * @param {boolean} useVirtual - Whether to use virtual reports or real stored reports
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReports: async (useVirtual = true) => {
    if (useVirtual) {
      return reportService.getVirtualReports();
    } else {
      return reportService.getRealReports();
    }
  },
  
  /**
   * Get real reports from API
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getRealReports: async () => {
    try {
      const response = await api.get('/reports/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching reports:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to fetch reports. Please try again.'
      };
    }
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
          error: scansResponse.error || 'Failed to fetch scans.'
        };
      }
      
      // Extract scans array from response
      let scans = [];
      if (Array.isArray(scansResponse.data)) {
        scans = scansResponse.data;
      } else if (scansResponse.data && Array.isArray(scansResponse.data.results)) {
        scans = scansResponse.data.results;
      }
      
      // For each scan, get complete results for better reporting
      const reportsPromises = scans.map(async scan => {
        // For completed scans, fetch detailed results
        if (scan.status === 'completed' && (!scan.results || scan.results.length === 0)) {
          try {
            const resultsResponse = await scanService.getScanResults(scan.id);
            if (resultsResponse.success) {
              // Merge scan with results
              return reportService.convertScanToReport({
                ...scan,
                results: resultsResponse.data.results || []
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
      console.error('Error getting virtual reports:', error);
      return { 
        success: false, 
        error: 'Failed to generate reports from scans. Please try again.'
      };
    }
  },
  
  /**
   * Get a single report by ID (virtual or real)
   * @param {string} reportId - The ID of the report to fetch
   * @param {boolean} useVirtual - Whether to use virtual or real reports
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportById: async (reportId, useVirtual = true) => {
    if (useVirtual) {
      return reportService.getVirtualReportById(reportId);
    } else {
      return reportService.getRealReportById(reportId);
    }
  },
  
  /**
   * Get a single report by ID (converted from a scan)
   * @param {string} reportId - The ID of the report (same as scan ID)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getVirtualReportById: async (reportId) => {
    try {
      // Use scanService.getScanWithResults for complete data in one request
      const scanResponse = await scanService.getScanWithResults(reportId);
      
      if (!scanResponse.success) {
        return { 
          success: false, 
          error: scanResponse.error || 'Failed to fetch scan details.'
        };
      }
      
      // Convert the scan to a report format
      const report = reportService.convertScanToReport(scanResponse.data);
      
      return { success: true, data: report };
    } catch (error) {
      console.error(`Error getting virtual report ${reportId}:`, error);
      return { 
        success: false, 
        error: 'Failed to generate report from scan. Please try again.'
      };
    }
  },
  
  /**
   * Get a single real report by ID
   * @param {string} reportId - The ID of the report
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getRealReportById: async (reportId) => {
    try {
      const response = await api.get(`/reports/${reportId}/`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error(`Error fetching report ${reportId}:`, error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to fetch report details. Please try again.'
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
      content: 100
    };
    // const securityScore = calculateSecurityScore(results);
    const securityScore = scan.security_score !== undefined 
    ? scan.security_score 
    : calculateSecurityScore(results); // Fall back to calculatio

      // Group results by category
    const resultsByCategory = {};
    (scan.results || []).forEach(result => {
      const category = result.category?.toLowerCase() || 'unknown';
      if (!resultsByCategory[category]) {
        resultsByCategory[category] = [];
      }
      resultsByCategory[category].push(result);
    });

      // Calculate score for each category
    const severityWeights = {
      'critical': 20,
      'high': 10,
      'medium': 5,
      'low': 2,
      'info': 0
    };
    
    Object.entries(resultsByCategory).forEach(([category, results]) => {
      if (category in categoryScores) {
        let deduction = 0;
        results.forEach(result => {
          deduction += severityWeights[result.severity?.toLowerCase() || 'info'] || 0;
        });
        categoryScores[category] = Math.max(0, Math.min(100, 100 - deduction));
      }
    });
    
    // Create a virtual report object from the scan
    return {
      id: scan.id,
      scan_id: scan.id,  // Reference to original scan
      user: scan.user,
      name: scan.name || `Report for ${scan.target_url}`,
      target_url: scan.target_url,
      status: scan.status,
      status_display: scan.status.charAt(0).toUpperCase() + scan.status.slice(1), // Capitalize for display
      created_at: scan.created_at,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      scan_types: scan.scan_types || [],
      highest_severity: highestSeverity,
      highest_severity_display: highestSeverity.charAt(0).toUpperCase() + highestSeverity.slice(1),
      security_score: securityScore,
      category_scores: categoryScores,
      findings_summary: {
        counts: findingCounts,
        total: Object.values(findingCounts).reduce((a, b) => a + b, 0)
      },
      category_counts: categoryResults,
      // Include the original scan results for reference
      results: results,
      is_virtual: true  // Flag to indicate this is a virtual report
    };
  },
  
  /**
   * Generate a PDF report for a single scan or report
   * @param {string} reportId - The ID of the report/scan
   * @param {boolean} useVirtual - Whether this is a virtual report (scan-based) or real report
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  generatePdf: async (reportId, useVirtual = true) => {
    try {
      // Determine the endpoint based on whether we're using virtual or real reports
      const endpoint = useVirtual 
        ? `scanner/scans/${reportId}/pdf/` 
        : `reports/${reportId}/pdf/`;
      
      const response = await api.get(endpoint, {
        responseType: 'blob',
      });
      
      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers['content-disposition'];
      let filename = `security-report-${reportId}.pdf`;
      
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch && filenameMatch.length > 1) {
          filename = filenameMatch[1];
        }
      }
      
      // Create a download link
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      link.parentNode.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      return { success: true };
    } catch (error) {
      console.error(`Error generating PDF for report ${reportId}:`, error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to generate PDF report. Please try again.'
      };
    }
  },
  
  /**
   * Export reports in the requested format
   * @param {Array<string>} reportIds - Array of report IDs to export
   * @param {string} format - Export format (pdf, csv, json, html)
   * @param {Object} options - Additional export options
   * @param {boolean} useVirtual - Whether to use virtual or real reports
   */
  exportReports: async (reportIds, format = 'pdf', options = {}, useVirtual = true) => {
    try {
      if (useVirtual) {
        // For virtual reports (scan-based)
        if (format === 'pdf') {
          // For simplicity, if only one report, just download it directly
          if (reportIds.length === 1) {
            return await reportService.generatePdf(reportIds[0], true);
          }
          
          // For multiple reports, download the first one and inform the user
          const result = await reportService.generatePdf(reportIds[0], true);
          if (result.success) {
            alert(`Exported 1 of ${reportIds.length} reports. Multiple report export is not yet supported.`);
          }
          return result;
        } else {
          // For other formats, let the user know this isn't supported
          alert(`Export format "${format}" is not supported for virtual reports.`);
          return { 
            success: false, 
            error: `Export format "${format}" is not supported for virtual reports.`
          };
        }
      } else {
        // For real reports, use the backend API
        const response = await api.post('/reports/export/', {
          report_ids: reportIds,
          format,
          options
        }, {
          responseType: 'blob', // Important for file downloads
        });
        
        // Create a download for the returned file
        const contentDisposition = response.headers['content-disposition'];
        let filename = 'report-export';
        
        // Extract filename from Content-Disposition header if available
        if (contentDisposition) {
          const filenameMatch = contentDisposition.match(/filename="(.+)"/);
          if (filenameMatch && filenameMatch.length > 1) {
            filename = filenameMatch[1];
          }
        } else {
          // Fallback filename with timestamp
          const dateStr = new Date().toISOString().split('T')[0];
          filename = `security-report-${dateStr}.${format}`;
        }
        
        // Create a Blob and download link
        const blob = new Blob([response.data], { 
          type: format === 'pdf' ? 'application/pdf' : 
                format === 'csv' ? 'text/csv' :
                format === 'json' ? 'application/json' : 'text/html' 
        });
        
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        
        // Clean up
        link.parentNode.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        return { success: true };
      }
    } catch (error) {
      console.error('Error exporting reports:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to export reports. Please try again.'
      };
    }
  },
  
  /**
   * Create a report from a completed scan 
   * This converts a virtual report to a real, persisted report
   * @param {string} scanId - The ID of the completed scan
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  createReportFromScan: async (scanId) => {
    try {
      // Fetch the scan to check status
      const scanResponse = await scanService.getScan(scanId);
      
      if (!scanResponse.success) {
        return { 
          success: false, 
          error: 'Failed to fetch scan details.' 
        };
      }
      
      if (scanResponse.data.status !== 'completed') {
        return { 
          success: false, 
          error: 'Cannot create a report from an incomplete scan.' 
        };
      }
      
      // Create a report from the scan using the API
      const response = await api.post(`/scanner/scans/${scanId}/create-report/`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error(`Error creating report from scan ${scanId}:`, error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to create report from scan. Please try again.'
      };
    }
  }
};

export default reportService;