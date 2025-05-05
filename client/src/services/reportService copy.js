// frontend/src/services/reportService.js

import api from './api';

export const reportService = {
  /**
   * Fetch all reports for the current user
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReports: async () => {
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
   * Fetch a single report by ID
   * @param {string} reportId - The ID of the report to fetch
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportById: async (reportId) => {
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
   * Export selected reports in the requested format
   * @param {Array<string>} reportIds - Array of report IDs to export
   * @param {string} format - Export format (pdf, csv, json, html)
   * @param {Object} options - Additional export options
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  exportReports: async (reportIds, format = 'pdf', options = {}) => {
    try {
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
    } catch (error) {
      console.error('Error exporting reports:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to export reports. Please try again.'
      };
    }
  },

  /**
   * Generate a PDF report for a single scan
   * @param {string} reportId - The ID of the report to generate PDF for
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  generatePdf: async (reportId) => {
    try {
      const response = await api.get(`/reports/${reportId}/pdf/`, {
        responseType: 'blob',
      });
      
      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers['content-disposition'];
      let filename = `report-${reportId}.pdf`;
      
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
   * Delete a report
   * @param {string} reportId - The ID of the report to delete
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  deleteReport: async (reportId) => {
    try {
      await api.delete(`/reports/${reportId}/`);
      return { success: true };
    } catch (error) {
      console.error(`Error deleting report ${reportId}:`, error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to delete report. Please try again.'
      };
    }
  },

  /**
   * Update report details (like name, notes)
   * @param {string} reportId - The ID of the report to update
   * @param {Object} data - The data to update
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  updateReport: async (reportId, data) => {
    try {
      const response = await api.patch(`/reports/${reportId}/`, data);
      return { success: true, data: response.data };
    } catch (error) {
      console.error(`Error updating report ${reportId}:`, error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to update report. Please try again.'
      };
    }
  },

  /**
   * Fetch report statistics (vulnerabilities by severity, etc.)
   * @returns {Promise<Object>} Response object with success flag and data/error
   */
  getReportStats: async () => {
    try {
      const response = await api.get('/reports/statistics/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching report statistics:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Failed to fetch report statistics. Please try again.'
      };
    }
  }
};

export default reportService;