// frontend/src/services/scanService.js

import api from './api';
import { processScanResults } from '../models/ScanResultsModel';
import { calculateSecurityScore, getSecurityRating } from '../utils/securityUtils';

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
      // Use the correct endpoint for the custom action in the ViewSet
      const response = await api.delete('/scanner/scans/history/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error deleting scan history:', error);
      return { 
        success: false, 
        error: error.response?.data || 'Failed to delete scan history' 
      };
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
  
  // New method that combines scan data and results
  getScanWithResults: async (id) => {
    try {
      const scanResponse = await api.get(`/scanner/scans/${id}/`);
      const resultsResponse = await api.get(`/scanner/scans/${id}/results/`);
      
      const processedData = processScanResults(
        scanResponse.data,
        resultsResponse.data.results || []
      );
      
      return { success: true, data: processedData };
    } catch (error) {
      console.error('Error fetching scan with results:', error);
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
  calculateSecurityScore,
  
  // Get risk level text based on security score
  getRiskLevelText: getSecurityRating
};