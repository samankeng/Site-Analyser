// frontend/src/contexts/AuthContext.js - Updated with OAuth support

import { createContext, useContext, useEffect, useState } from "react";
import { authService } from "../services/authService";
import { getToken } from "../utils/storage";

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
        const storedUser = localStorage.getItem("user");
        if (storedUser) {
          setUser(JSON.parse(storedUser));
        }

        // Then verify with the server
        try {
          const response = await authService.getUserProfile();
          if (response.success) {
            setUser(response.data);
            localStorage.setItem("user", JSON.stringify(response.data));
          } else {
            // Token invalid, logout
            authService.logout();
            setUser(null);
          }
        } catch (error) {
          console.error("Failed to fetch user profile:", error);
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

  // Set user from social authentication
  const setSocialUser = (userData) => {
    setUser(userData);
    localStorage.setItem("user", JSON.stringify(userData));
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
      localStorage.setItem("user", JSON.stringify(response.data));
    }

    return response;
  };

  // Disconnect social account
  const disconnectSocialAccount = async (provider) => {
    setLoading(true);
    const response = await authService.disconnectSocialAccount(provider);
    setLoading(false);

    if (response.success) {
      // Refresh user profile to get updated social connections
      const profileResponse = await authService.getUserProfile();
      if (profileResponse.success) {
        setUser(profileResponse.data);
        localStorage.setItem("user", JSON.stringify(profileResponse.data));
      }
    }

    return response;
  };

  // Generate new API key
  const generateApiKey = async () => {
    setLoading(true);
    const response = await authService.generateApiKey();
    setLoading(false);

    if (response.success) {
      // Update user with new API key
      const updatedUser = { ...user, api_key: response.data.api_key };
      setUser(updatedUser);
      localStorage.setItem("user", JSON.stringify(updatedUser));
    }

    return response;
  };

  // Helper functions
  const isProfileComplete = () => {
    if (!user) return false;
    return !!(
      user.first_name &&
      user.last_name &&
      user.company &&
      user.job_title
    );
  };

  const getConnectedProviders = () => {
    if (!user || !user.social_profiles) return [];
    return user.social_profiles.map((profile) => profile.provider);
  };

  const canDisconnectProvider = (provider) => {
    if (!user) return false;

    const connectedProviders = getConnectedProviders();
    const hasPassword = !user.is_social_account || user.has_usable_password;
    const hasOtherProviders =
      connectedProviders.filter((p) => p !== provider).length > 0;

    return hasPassword || hasOtherProviders;
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    updateProfile,
    setSocialUser,
    disconnectSocialAccount,
    generateApiKey,
    isAuthenticated: !!user,
    isProfileComplete: isProfileComplete(),
    connectedProviders: getConnectedProviders(),
    canDisconnectProvider,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
