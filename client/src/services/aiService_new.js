// Fixed aiService.js with enhanced error handling

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

  // Fixed: Get executive summary for a scan
  getExecutiveSummary: async (scanId) => {
    // Validate scanId before making API call
    if (!scanId || scanId === 'undefined') {
      console.error('Invalid scanId provided to getExecutiveSummary:', scanId);
      return { success: false, error: 'Invalid scan ID' };
    }
    
    try {
      // Remove the duplicate /api/ prefix that was causing the 404 error
      const response = await api.get(`/ai-analyzer/analyses/executive_summary/?scan_id=${scanId}`);
      console.log('Executive summary response:', response);
      
      // Validate response format
      if (!response?.data) {
        return { 
          success: true, 
          data: {
            summary: '',
            analysisId: null
          }
        };
      }
      
      return { 
        success: true, 
        data: {
          summary: response.data.summary || 'No executive summary available.',
          analysisId: response.data.analysis_id || null
        }
      };
    } catch (error) {
      console.error('Error in getExecutiveSummary:', error);
      
      // Check specifically for 404 errors
      if (error?.response?.status === 404) {
        // Try an alternative URL format as a fallback
        try {
          console.log('Trying alternative URL format for executive summary');
          const altResponse = await api.get(`/ai-analyzer/analyses/${scanId}/executive_summary/`);
          
          if (altResponse?.data) {
            return { 
              success: true, 
              data: {
                summary: altResponse.data.summary || 'No executive summary available.',
                analysisId: altResponse.data.analysis_id || null
              }
            };
          }
        } catch (altError) {
          console.error('Alternative URL also failed:', altError);
        }
        
        return { 
          success: false, 
          error: 'Executive summary endpoint not found: the API may not be implemented', 
          notFound: true 
        };
      }
      
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

  // Fixed: Get LLM analysis results with corrected URL path
  getLlmAnalysis: async (analysisId) => {
    // Validate analysisId before making API call
    if (!analysisId || analysisId === 'undefined') {
      console.error('Invalid analysisId provided to getLlmAnalysis:', analysisId);
      return { success: false, error: 'Invalid analysis ID' };
    }
    
    try {
      // Remove duplicate /api/ prefix
      const response = await api.get(`/ai-analyzer/analyses/llm_analysis/?analysis_id=${analysisId}`);
      console.log('LLM analysis response:', response);
      
      return { 
        success: true, 
        data: response.data || {}
      };
    } catch (error) {
      console.error('Error in getLlmAnalysis:', error);
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

  // Fixed: Get LLM-specific recommendations with corrected URL path
  getLlmRecommendations: async (analysisId) => {
    // Validate analysisId before making API call
    if (!analysisId || analysisId === 'undefined') {
      console.error('Invalid analysisId provided to getLlmRecommendations:', analysisId);
      return { success: false, error: 'Invalid analysis ID' };
    }
    
    try {
      // Remove duplicate /api/ prefix
      const response = await api.get(`/ai-analyzer/recommendations/llm_recommendations/?analysis_id=${analysisId}`);
      console.log('LLM recommendations response:', response);
      
      // Ensure we're returning an array
      let recommendationsData = response.data;
      if (!Array.isArray(recommendationsData)) {
        if (Array.isArray(recommendationsData?.results)) {
          recommendationsData = recommendationsData.results;
        } else if (Array.isArray(recommendationsData?.items)) {
          recommendationsData = recommendationsData.items;
        } else {
          console.warn('Unknown API response format for LLM recommendations, defaulting to empty array');
          recommendationsData = [];
        }
      }
      
      return { 
        success: true, 
        data: recommendationsData
      };
    } catch (error) {
      console.error('Error in getLlmRecommendations:', error);
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