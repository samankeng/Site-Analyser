// frontend/src/services/anomalyService.js

import api from './api';

// Using named constant that we'll export as default
const anomalyService = {
  getAnomaliesForScan: async (scanId) => {
    // Validate scanId before making API call
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to getAnomaliesForScan:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      // Use proper URL structure matching the backend API
      const response = await api.get(`/ai-analyzer/anomalies/for_scan/?scan_id=${scanId}`);
      console.log('Get anomalies response:', response); // Debug log
      
      // Fix for API response format issue:
      // Ensure we're returning an array even if the API returns an object
      let anomaliesData = response.data;
      
      // Check if the response is an object with a results or items property containing the anomalies
      if (!Array.isArray(anomaliesData) && typeof anomaliesData === 'object') {
        if (Array.isArray(anomaliesData.results)) {
          anomaliesData = anomaliesData.results;
        } else if (Array.isArray(anomaliesData.items)) {
          anomaliesData = anomaliesData.items;
        } else if (Object.keys(anomaliesData).length > 0 && typeof anomaliesData.id === 'string') {
          // If it's a single object with an ID, wrap it in an array
          anomaliesData = [anomaliesData];
        } else {
          // If we can't determine the format, assume empty array
          console.warn('Unknown API response format for anomalies, defaulting to empty array');
          anomaliesData = [];
        }
      }
      
      return { success: true, data: anomaliesData };
    } catch (error) {
      console.error('Error in getAnomaliesForScan:', error);
      // Ensure error is a string
      let errorMessage = 'Unknown error';
      if (typeof error === 'string') {
        errorMessage = error;
      } else if (error?.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error?.response?.data) {
        errorMessage = typeof error.response.data === 'string' 
          ? error.response.data 
          : JSON.stringify(error.response.data);
      } else if (error?.message) {
        errorMessage = error.message;
      }
      return { success: false, error: errorMessage };
    }
  },

  getAnomalyStats: async () => {
    try {
      const response = await api.get('/ai-analyzer/anomalies/stats/');
      console.log('Get anomaly stats response:', response); // Debug log
      
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error in getAnomalyStats:', error);
      // Ensure error is a string
      let errorMessage = 'Unknown error';
      if (typeof error === 'string') {
        errorMessage = error;
      } else if (error?.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error?.response?.data) {
        errorMessage = typeof error.response.data === 'string' 
          ? error.response.data 
          : JSON.stringify(error.response.data);
      } else if (error?.message) {
        errorMessage = error.message;
      }
      return { success: false, error: errorMessage };
    }
  },

  markAsFalsePositive: async (anomalyId) => {
    // Validate anomalyId before making API call
    if (!anomalyId || anomalyId === 'undefined') {
      console.error('Invalid anomalyId provided to markAsFalsePositive:', anomalyId);
      return { success: false, error: 'Invalid anomaly ID' };
    }
    
    try {
      const response = await api.post(`/ai-analyzer/anomalies/${anomalyId}/false_positive/`);
      console.log('Mark as false positive response:', response); // Debug log
      
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error in markAsFalsePositive:', error);
      // Ensure error is a string
      let errorMessage = 'Unknown error';
      if (typeof error === 'string') {
        errorMessage = error;
      } else if (error?.response?.data?.detail) {
        errorMessage = error.response.data.detail;
      } else if (error?.response?.data) {
        errorMessage = typeof error.response.data === 'string' 
          ? error.response.data 
          : JSON.stringify(error.response.data);
      } else if (error?.message) {
        errorMessage = error.message;
      }
      return { success: false, error: errorMessage };
    }
  }
};

// Export as default (this is what causes the import issue)
export default anomalyService;