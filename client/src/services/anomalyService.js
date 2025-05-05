// client/src/services/anomalyService.js

import api from './api';

export const anomalyService = {
  // Get anomalies for a specific scan
  getAnomaliesForScan: async (scanId) => {
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to getAnomaliesForScan:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      const response = await api.get(`/ai-analyzer/anomalies/?scan_id=${scanId}`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching anomalies:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get real-time anomaly status for a scan
  getAnomalyStatus: async (scanId) => {
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to getAnomalyStatus:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      const response = await api.get(`/ai-analyzer/anomalies/${scanId}/status/`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching anomaly status:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Train the anomaly detection model (admin only)
  trainModel: async () => {
    try {
      const response = await api.post('/ai-analyzer/anomaly-model/train/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error training anomaly model:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get model status and metrics
  getModelStatus: async () => {
    try {
      const response = await api.get('/ai-analyzer/anomaly-model/status/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching model status:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Configure anomaly detection threshold (admin only)
  configureThreshold: async (threshold) => {
    try {
      const response = await api.post('/ai-analyzer/anomaly-model/configure/', { threshold });
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error configuring threshold:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get historical anomaly trend data
  getAnomalyTrends: async (timeframe = '7d') => {
    try {
      const response = await api.get(`/ai-analyzer/anomalies/trends/?timeframe=${timeframe}`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching anomaly trends:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Mark an anomaly as false positive
  markAsFalsePositive: async (anomalyId) => {
    try {
      const response = await api.post(`/ai-analyzer/anomalies/${anomalyId}/false-positive/`);
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error marking anomaly as false positive:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get anomaly detection statistics
  getAnomalyStats: async () => {
    try {
      const response = await api.get('/ai-analyzer/anomalies/stats/');
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error fetching anomaly stats:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  }
};

export default anomalyService;