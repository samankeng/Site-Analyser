// frontend/src/services/authService.js - Updated with OAuth support

import { clearTokens, setTokens } from "../utils/storage";
import api from "./api";

// Export the authService object directly
const authService = {
  // Login user
  login: async (email, password) => {
    try {
      const response = await api.post("/auth/login/", { email, password });
      const { access, refresh, user } = response.data;

      // Store tokens and user data
      setTokens(access, refresh);
      localStorage.setItem("user", JSON.stringify(user));

      return { success: true, user };
    } catch (error) {
      return {
        success: false,
        error:
          error.response?.data?.detail ||
          "Login failed. Please check your credentials.",
      };
    }
  },

  // Register new user
  register: async (userData) => {
    try {
      const response = await api.post("/auth/register/", userData);
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || "Registration failed. Please try again.",
      };
    }
  },

  // Get current user profile
  getUserProfile: async () => {
    try {
      const response = await api.get("/auth/profile/");
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Update user profile
  updateProfile: async (userData) => {
    try {
      const response = await api.put("/auth/profile/", userData);
      return { success: true, data: response.data };
    } catch (error) {
      return { success: false, error: error.response?.data };
    }
  },

  // Logout user
  logout: () => {
    clearTokens();
    localStorage.removeItem("user");
    localStorage.removeItem("oauth_redirect");
  },

  // ========================================
  // OAuth-related methods
  // ========================================

  // Exchange social auth token for JWT
  exchangeSocialToken: async (provider, accessToken) => {
    try {
      const response = await api.post("/auth/social/token/", {
        provider,
        access_token: accessToken,
      });

      const { access, refresh, user } = response.data;

      // Store tokens and user data
      setTokens(access, refresh);
      localStorage.setItem("user", JSON.stringify(user));

      return { success: true, user };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || "Social authentication failed",
      };
    }
  },

  // Exchange GitHub code for tokens
  exchangeGitHubCode: async (code, state) => {
    try {
      const response = await api.post("/auth/github/exchange/", {
        code,
        state,
      });

      if (response.data.success) {
        const { access, refresh, user } = response.data;

        // Store tokens and user data
        setTokens(access, refresh);
        localStorage.setItem("user", JSON.stringify(user));

        return { success: true, user };
      } else {
        return {
          success: false,
          error: response.data.error || "GitHub authentication failed",
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.error || "GitHub authentication failed",
      };
    }
  },

  // Disconnect social account
  disconnectSocialAccount: async (provider) => {
    try {
      const response = await api.post("/auth/social/disconnect/", { provider });
      return { success: true, message: response.data.message };
    } catch (error) {
      return {
        success: false,
        error:
          error.response?.data?.error || "Failed to disconnect social account",
      };
    }
  },

  // Export user data
  exportUserData: async () => {
    try {
      const response = await api.get("/auth/user-data/export/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || "Failed to export user data.",
      };
    }
  },

  // Deactivate user account
  deactivateAccount: async () => {
    try {
      const response = await api.post("/auth/deactivate-account/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || "Failed to deactivate account.",
      };
    }
  },

  // Generate new API key
  generateApiKey: async () => {
    try {
      const response = await api.post("/auth/api-keys/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || "Failed to generate API key.",
      };
    }
  },

  // Get user's API keys
  getApiKeys: async () => {
    try {
      const response = await api.get("/auth/api-keys/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: error.response?.data || "Failed to retrieve API keys.",
      };
    }
  },
};

// Export as a named export and as a default export to ensure compatibility
export { authService };
export default authService;
