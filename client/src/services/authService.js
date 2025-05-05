// frontend/src/services/authService.js

import api from './api';
import { setTokens, clearTokens } from '../utils/storage';

export const authService = {
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
  }
};
