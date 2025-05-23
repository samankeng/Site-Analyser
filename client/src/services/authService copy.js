// frontend/src/services/authService.js

import api from './api';
import { setTokens, clearTokens } from '../utils/storage';

// Export the authService object directly
const authService = {
  // Login user
  login: async (email, password) => {
    try {
      const response = await api.post('/auth/login/', { email, password });
      const { access, refresh, user } = response.data;
      
      // Store tokens and user data
      setTokens(access, refresh);
      localStorage.setItem('user', JSON.stringify(user));
      
      return { success: true, user };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Login failed. Please check your credentials.'
      };
    }
  },
  
  // Register new user
  register: async (userData) => {
    try {
      const response = await api.post('/auth/register/', userData);
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data || 'Registration failed. Please try again.'
      };
    }
  },
  
  // Get current user profile
  getUserProfile: async () => {
    try {
      const response = await api.get('/auth/profile/');
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },
  
  // Update user profile
  updateProfile: async (userData) => {
    try {
      const response = await api.put('/auth/profile/', userData);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },
  
  // Logout user
  logout: () => {
    clearTokens();
    localStorage.removeItem('user');
  },
  
  // Export user data
  exportUserData: async () => {
    try {
      const response = await api.get('/auth/user-data/export/');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data || 'Failed to export user data.' 
      };
    }
  },
  
  // Deactivate user account
  deactivateAccount: async () => {
    try {
      const response = await api.post('/auth/deactivate-account/');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data || 'Failed to deactivate account.' 
      };
    }
  },
  
  // Generate new API key
  generateApiKey: async () => {
    try {
      const response = await api.post('/auth/api-keys/');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data || 'Failed to generate API key.' 
      };
    }
  },
  
  // Get user's API keys
  getApiKeys: async () => {
    try {
      const response = await api.get('/auth/api-keys/');
      return { success: true, data: response.data };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data || 'Failed to retrieve API keys.' 
      };
    }
  }
};

// Export as a named export and as a default export to ensure compatibility
export { authService };
export default authService;