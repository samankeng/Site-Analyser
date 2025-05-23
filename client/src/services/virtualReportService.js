// frontend/src/services/virtualReportService.js

import api from './api';
import { scanService } from './scanService';

/**
 * Service that creates virtual reports from scans
 * This avoids the need to store separate report objects in the database
 */
export const virtualReportService = {
  /**
   * Convert a scan object to a report format
   * @param {Object} scan - Scan object from API
   * @returns {Object} Report-formatted object
   */
  convertScanToReport: (scan) => {
    // Calculate findings counts based on scan results
    const findingCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let highestSeverity = 'none';
    
    // Process scan results if they exist
    if (scan.results && Array.isArray(scan.results)) {
      scan.results.forEach(result => {
        const severity = result.severity?.toLowerCase();
        if (severity && findingCounts.hasOwnProperty(severity)) {
          findingCounts[severity]++;
          
          // Update highest severity
          const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };
          if (severityOrder[severity] > severityOrder[highestSeverity || 'none']) {
            highestSeverity = severity;
          }
        }
      });
    }
    
    // Create a virtual report object from the scan
    return {
      id: scan.id,
      scan_id: scan.id,  // Reference to original scan
      user: scan.user,
      name: `Report for ${scan.target_url}`,
      target_url: scan.target_url,
      status: scan.status,
      status_display: scan.status.charAt(0).toUpperCase() + scan.status.slice(1), // Capitalize for display
      created_at: scan.created_at,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      scan_types: scan.scan_types || [],
      highest_severity: highestSeverity,
      findings_summary: {
        counts: findingCounts,
        total: Object.values(findingCounts).reduce((a, b) => a + b, 0)
      },
      // Include the original scan results for reference
      results: scan.results || [],
      is_virtual: true  // Flag to indicate this is a virtual report
    };
  },
  
  /**
   * Get all reports (converted from scans)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReports: async () => {
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
      
      // Convert each scan to a report format
      const reports = scans.map(scan => virtualReportService.convertScanToReport(scan));
      
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
   * Get a single report by ID (converted from a scan)
   * @param {string} reportId - The ID of the report (same as scan ID)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportById: async (reportId) => {
    try {
      // Fetch the scan by ID
      const scanResponse = await scanService.getScan(reportId);
      
      if (!scanResponse.success) {
        return { 
          success: false, 
          error: scanResponse.error || 'Failed to fetch scan details.'
        };
      }
      
      // Convert the scan to a report format
      const report = virtualReportService.convertScanToReport(scanResponse.data);
      
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
   * Generate a PDF report for a single scan
   * @param {string} reportId - The ID of the report (same as scan ID)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  generatePdf: async (reportId) => {
    try {
      // Use the PDF endpoint we added to ScanViewSet
      const response = await api.get(`scanner/scans/${reportId}/pdf/`, {
        responseType: 'blob',
      });
      
      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers['content-disposition'];
      let filename = `security-scan-${reportId}.pdf`;
      
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
   * Since we don't have a true report export endpoint, this handles single reports via PDF
   * and provides appropriate user feedback for multiple reports
   */
  exportReports: async (reportIds, format = 'pdf', options = {}) => {
    try {
      // For virtual reports, since we don't have a real export endpoint,
      // we'll download PDFs for each scan and package them
      
      if (format === 'pdf') {
        // For simplicity, if only one report, just download it directly
        if (reportIds.length === 1) {
          return await virtualReportService.generatePdf(reportIds[0]);
        }
        
        // For multiple reports, download the first one and inform the user
        const result = await virtualReportService.generatePdf(reportIds[0]);
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
    } catch (error) {
      console.error('Error exporting reports:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to export reports. Please try again.'
      };
    }
  }
};

export default virtualReportService;