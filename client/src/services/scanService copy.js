// frontend/src/services/scanService.js

import api from './api';

export const scanService = {
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
  
  // Create a new scan
  createScan: async (scanData) => {
    try {
      const response = await api.post('/scanner/scans/', scanData);
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
  
  // Get scan results
  getScanResults: async (scanId) => {
    try {
      const response = await api.get(`/scanner/scans/${scanId}/results/`);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },
  
  // Download scan report as PDF
  downloadScanReport: async (scanId) => {
    try {
      const response = await api.get(`/scanner/scans/${scanId}/pdf/`, {
        responseType: 'blob', // Important for correct handling of binary data
      });
      
      // Create a download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Extract filename from Content-Disposition header if available
      const contentDisposition = response.headers['content-disposition'];
      let filename = `security-scan-${scanId}.pdf`;
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
        if (filenameMatch && filenameMatch.length > 1) {
          filename = filenameMatch[1];
        }
      }
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
      
      return { success: true };
    } catch (error) {
      console.error('Error downloading report:', error);
      return { 
        success: false, 
        error: error.response?.data || 'Failed to download report' 
      };
    }
  },
  
  // Calculate security score based on scan results
  calculateSecurityScore: (results) => {
    if (!results || !Array.isArray(results) || results.length === 0) return 100;

    const severityWeights = {
      'critical': 20,
      'high': 10,
      'medium': 5,
      'low': 2,
      'info': 0
    };

    // Count findings by severity
    const severityCounts = {};
    results.forEach(result => {
      const severity = result.severity.toLowerCase();
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;
    });

    // Calculate total deduction
    let totalDeduction = 0;
    Object.entries(severityCounts).forEach(([severity, count]) => {
      totalDeduction += count * (severityWeights[severity] || 0);
    });

    // Ensure score doesn't go below 0
    return Math.max(0, 100 - Math.min(100, totalDeduction));
  },
  
  // Get risk level text based on security score
  getRiskLevelText: (score) => {
    if (score >= 90) return "Very Secure";
    if (score >= 80) return "Secure";
    if (score >= 70) return "Moderately Secure";
    if (score >= 60) return "Needs Improvement";
    if (score >= 40) return "Insecure";
    return "Critically Insecure";
  }
};