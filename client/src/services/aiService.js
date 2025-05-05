// frontend/src/services/aiService.js

import api from './api';

export const aiService = {
  // Trigger AI analysis for a scan
  analyzeScan: async (scanId) => {
    // Validate scanId before making API call
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to analyzeScan:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      const response = await api.post('/ai-analyzer/analyses/analyze/', { scan_id: scanId });
      console.log('Analysis response:', response); // Debug log
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Error in analyzeScan:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get AI analyses for a scan
  getAnalysesForScan: async (scanId) => {
    // Validate scanId before making API call
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to getAnalysesForScan:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      // Use proper URL structure matching the backend API
      const response = await api.get(`/ai-analyzer/analyses/for_scan/?scan_id=${scanId}`);
      console.log('Get analyses response:', response); // Debug log
      
      // Fix for API response format issue:
      // Ensure we're returning an array even if the API returns an object
      let analysesData = response.data;
      
      // Check if the response is an object with a results or items property containing the analyses
      if (!Array.isArray(analysesData) && typeof analysesData === 'object') {
        if (Array.isArray(analysesData.results)) {
          analysesData = analysesData.results;
        } else if (Array.isArray(analysesData.items)) {
          analysesData = analysesData.items;
        } else if (Object.keys(analysesData).length > 0 && typeof analysesData.id === 'string') {
          // If it's a single object with an ID, wrap it in an array
          analysesData = [analysesData];
        } else {
          // If we can't determine the format, assume empty array
          console.warn('Unknown API response format for analyses, defaulting to empty array');
          analysesData = [];
        }
      }
      
      return { success: true, data: analysesData };
    } catch (error) {
      console.error('Error in getAnalysesForScan:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  },
  
  // Get recommendations for an analysis
  getRecommendationsForAnalysis: async (analysisId) => {
    // Validate analysisId before making API call
    if (!analysisId || analysisId === 'undefined') {
      console.error('Invalid analysisId provided to getRecommendationsForAnalysis:', analysisId);
      return { success: false, error: 'Invalid analysis ID' };
    }
    
    try {
      // Use proper URL structure matching the backend API
      const response = await api.get(`/ai-analyzer/recommendations/for_analysis/?analysis_id=${analysisId}`);
      console.log('Get recommendations response:', response); // Debug log
      
      // Fix for API response format issue:
      // Ensure we're returning an array even if the API returns an object
      let recommendationsData = response.data;
      
      // Check if the response is an object with a results or items property containing the recommendations
      if (!Array.isArray(recommendationsData) && typeof recommendationsData === 'object') {
        if (Array.isArray(recommendationsData.results)) {
          recommendationsData = recommendationsData.results;
        } else if (Array.isArray(recommendationsData.items)) {
          recommendationsData = recommendationsData.items;
        } else if (Object.keys(recommendationsData).length > 0 && typeof recommendationsData.id === 'string') {
          // If it's a single object with an ID, wrap it in an array
          recommendationsData = [recommendationsData];
        } else {
          // If we can't determine the format, assume empty array
          console.warn('Unknown API response format for recommendations, defaulting to empty array');
          recommendationsData = [];
        }
      }
      
      return { success: true, data: recommendationsData };
    } catch (error) {
      console.error('Error in getRecommendationsForAnalysis:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.response?.data || error.message || 'Unknown error' 
      };
    }
  }
};