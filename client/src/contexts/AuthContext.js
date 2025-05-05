// frontend/src/contexts/AuthContext.js

import React, { createContext, useState, useEffect, useContext } from 'react';
import { authService } from '../services/authService';
import { getToken } from '../utils/storage';

// Create context
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // Check if user is authenticated on component mount
  useEffect(() => {
    const initAuth = async () => {
      // Check if token exists
      const token = getToken();
      
      if (token) {
        // Get user from local storage (faster)
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
          setUser(JSON.parse(storedUser));
        }
        
        // Then verify with the server
        try {
          const response = await authService.getUserProfile();
          if (response.success) {
            setUser(response.data);
            localStorage.setItem('user', JSON.stringify(response.data));
          } else {
            // Token invalid, logout
            authService.logout();
            setUser(null);
          }
        } catch (error) {
          console.error('Failed to fetch user profile:', error);
        }
      }
      
      setLoading(false);
    };
    
    initAuth();
  }, []);
  
  // Login function
  const login = async (email, password) => {
    setLoading(true);
    const response = await authService.login(email, password);
    setLoading(false);
    
    if (response.success) {
      setUser(response.user);
      return { success: true };
    }
    
    return { success: false, error: response.error };
  };
  
  // Register function
  const register = async (userData) => {
    setLoading(true);
    const response = await authService.register(userData);
    setLoading(false);
    return response;
  };
  
  // Logout function
  const logout = () => {
    authService.logout();
    setUser(null);
  };
  
  // Update profile function
  const updateProfile = async (userData) => {
    setLoading(true);
    const response = await authService.updateProfile(userData);
    setLoading(false);
    
    if (response.success) {
      setUser(response.data);
      localStorage.setItem('user', JSON.stringify(response.data));
    }
    
    return response;
  };
  
  const value = {
    user,
    loading,
    login,
    register,
    logout,
    updateProfile,
    isAuthenticated: !!user,
  };
  
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};