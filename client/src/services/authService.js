// frontend/src/services/authService.js - Enhanced with email verification and Microsoft OAuth (FIXED)

import { clearTokens, getToken, setTokens } from "../utils/storage";
import api from "./api";

// Helper to get auth headers
const getAuthHeaders = () => {
  const tokens = getToken();
  return {
    "Content-Type": "application/json",
    ...(tokens.access && { Authorization: `Bearer ${tokens.access}` }),
  };
};

// Enhanced error message helper
const getEnhancedErrorMessage = (error, defaultMessage, context = "") => {
  if (!error) return defaultMessage;

  // Check for network issues first
  if (!navigator.onLine) {
    return "No internet connection. Please check your network and try again.";
  }

  if (
    error.code === "NETWORK_ERROR" ||
    error.message?.includes("Network Error")
  ) {
    return "Network connection issue. Please check your internet connection and try again.";
  }

  if (error.name === "TimeoutError" || error.message?.includes("timeout")) {
    return "Request timed out. Please try again.";
  }

  // Extract error message from response
  let errorMessage = defaultMessage;

  if (error.response?.data?.error) {
    errorMessage = error.response.data.error;
  } else if (error.response?.data?.detail) {
    errorMessage = error.response.data.detail;
  } else if (error.response?.data && typeof error.response.data === "string") {
    errorMessage = error.response.data;
  } else if (error.message) {
    errorMessage = error.message;
  }

  // Context-specific error handling
  if (context === "oauth") {
    const message = errorMessage.toLowerCase();

    if (
      message.includes("bad_verification_code") ||
      message.includes("expired")
    ) {
      return "The authorization code has expired or been used already. Please try signing in again.";
    }
    if (message.includes("access_denied")) {
      return "Access was denied during authentication. Please authorize the application and try again.";
    }
    if (message.includes("invalid_client")) {
      return "Authentication service is not properly configured. Please contact support.";
    }
    if (
      message.includes("email not provided") ||
      message.includes("no email")
    ) {
      return "Your email address is required but not accessible. Please make your email public in your account settings.";
    }
    if (
      message.includes("rate limit") ||
      message.includes("too many requests")
    ) {
      return "Too many authentication attempts. Please wait a moment and try again.";
    }
  }

  // Email verification context
  if (context === "email_verification") {
    const message = errorMessage.toLowerCase();

    if (message.includes("invalid token") || message.includes("expired")) {
      return "The verification link has expired or is invalid. Please request a new verification email.";
    }
    if (message.includes("already verified")) {
      return "This email address has already been verified. You can sign in now.";
    }
  }

  // HTTP status code handling
  if (error.response?.status) {
    const status = error.response.status;

    if (status === 401) {
      return context === "login"
        ? "Invalid email or password. Please check your credentials."
        : "Authentication failed. Please try again.";
    }
    if (status === 403) {
      return "Access forbidden. You do not have permission to perform this action.";
    }
    if (status === 404) {
      return "The requested resource was not found.";
    }
    if (status === 400) {
      return context === "oauth"
        ? "Invalid authentication request. Please start the login process again."
        : errorMessage;
    }
    if (status >= 500) {
      return "Server temporarily unavailable. Please try again in a few minutes.";
    }
  }

  // Return processed error message (truncate if too long)
  return errorMessage.length > 150
    ? errorMessage.substring(0, 150) + "..."
    : errorMessage;
};

// Export the authService object directly
const authService = {
  // Login user (enhanced)
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
        error: getEnhancedErrorMessage(
          error,
          "Login failed. Please check your credentials.",
          "login"
        ),
      };
    }
  },

  // Register new user (enhanced with email verification)
  register: async (userData) => {
    try {
      const response = await api.post("/auth/register/", userData);
      return { success: true, data: response.data };
    } catch (error) {
      // For registration, we want to preserve detailed validation errors
      if (error.response?.status === 400 && error.response?.data) {
        // Return the detailed validation errors as-is
        return {
          success: false,
          error: error.response.data, // This preserves the field-specific errors
        };
      }

      // For other errors, use the enhanced error message
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Registration failed. Please try again.",
          "register"
        ),
      };
    }
  },

  // Email verification methods
  verifyEmail: async (token, uid) => {
    try {
      const response = await api.post("/auth/verify-email/", { token, uid });
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Email verification failed.",
          "email_verification"
        ),
      };
    }
  },

  resendVerificationEmail: async (email) => {
    try {
      const response = await api.post("/auth/resend-verification/", { email });
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to resend verification email.",
          "email_verification"
        ),
      };
    }
  },

  // Get current user profile (enhanced)
  getUserProfile: async () => {
    try {
      const response = await api.get("/auth/profile/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to load user profile.",
          "profile"
        ),
      };
    }
  },

  // Update user profile (enhanced)
  updateProfile: async (userData) => {
    try {
      const response = await api.put("/auth/profile/", userData);
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to update profile.",
          "profile"
        ),
      };
    }
  },

  // Logout user (unchanged)
  logout: () => {
    clearTokens();
    localStorage.removeItem("user");
    localStorage.removeItem("oauth_redirect");
    sessionStorage.removeItem("oauth_exchanged");
  },

  // ========================================
  // Enhanced OAuth-related methods
  // ========================================

  // Exchange social auth token for JWT (enhanced)
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
        error: getEnhancedErrorMessage(
          error,
          "Social authentication failed",
          "oauth"
        ),
      };
    }
  },

  // Exchange GitHub code for tokens (enhanced)
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
          error: getEnhancedErrorMessage(
            { response: { data: { error: response.data.error } } },
            "GitHub authentication failed",
            "oauth"
          ),
        };
      }
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "GitHub authentication failed",
          "oauth"
        ),
      };
    }
  },

  // Exchange Microsoft code for tokens (NEW)
  exchangeMicrosoftCode: async (code, state) => {
    try {
      const response = await api.post("/auth/microsoft/exchange/", {
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
          error: getEnhancedErrorMessage(
            { response: { data: { error: response.data.error } } },
            "Microsoft authentication failed",
            "oauth"
          ),
        };
      }
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Microsoft authentication failed",
          "oauth"
        ),
      };
    }
  },

  // Connect social account (enhanced)
  connectSocialAccount: async (provider) => {
    try {
      const response = await api.post("/auth/social/connect/", { provider });
      return { success: true, data: response.data };
    } catch (error) {
      // If endpoint doesn't exist, return redirect URL for OAuth flow
      if (error.response?.status === 404) {
        // For GitHub and Microsoft, we'll handle this client-side
        if (provider === "github" || provider === "microsoft") {
          return {
            success: true,
            data: {
              redirect_url: null, // Will be handled in component
            },
          };
        }
      }
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to connect social account",
          "oauth"
        ),
      };
    }
  },

  // Disconnect social account (enhanced)
  disconnectSocialAccount: async (provider) => {
    try {
      const response = await api.post("/auth/social/disconnect/", { provider });
      return { success: true, message: response.data.message };
    } catch (error) {
      let errorMessage = "Failed to disconnect social account";

      if (error.response?.data?.error) {
        const serverError = error.response.data.error;
        if (
          serverError.includes("cannot disconnect") ||
          serverError.includes("only authentication method")
        ) {
          errorMessage = `Cannot disconnect this account as it's your only login method. Please set up a password or connect another account first.`;
        } else {
          errorMessage = serverError;
        }
      } else if (error.response?.status === 404) {
        errorMessage = "Social account connection not found.";
      }

      return {
        success: false,
        error: getEnhancedErrorMessage(error, errorMessage, "disconnect"),
      };
    }
  },

  // Get connected accounts (enhanced)
  getConnectedAccounts: async () => {
    try {
      const response = await api.get("/auth/connected-accounts/");
      return { success: true, data: response.data };
    } catch (error) {
      // If endpoint doesn't exist, return default state
      if (error.response?.status === 404) {
        return {
          success: true,
          data: { google: false, github: false, microsoft: false },
        };
      }
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to fetch connected accounts",
          "connected-accounts"
        ),
      };
    }
  },

  // Password reset methods
  requestPasswordReset: async (email) => {
    try {
      const response = await api.post("/auth/password-reset/", { email });
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to send password reset email.",
          "password-reset"
        ),
      };
    }
  },

  confirmPasswordReset: async (token, uid, newPassword) => {
    try {
      const response = await api.post("/auth/password-reset-confirm/", {
        token,
        uid,
        new_password: newPassword,
      });
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to reset password.",
          "password-reset"
        ),
      };
    }
  },

  // Export user data (enhanced)
  exportUserData: async () => {
    try {
      const response = await api.get("/auth/user-data/export/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to export user data.",
          "export"
        ),
      };
    }
  },

  // Deactivate user account (enhanced)
  deactivateAccount: async () => {
    try {
      const response = await api.post("/auth/deactivate-account/");
      return { success: true, data: response.data };
    } catch (error) {
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to deactivate account.",
          "deactivate"
        ),
      };
    }
  },

  // Generate new API key (enhanced)
  generateApiKey: async () => {
    try {
      const response = await api.post("/auth/api-keys/");
      return { success: true, data: response.data };
    } catch (error) {
      // If endpoint doesn't exist
      if (error.response?.status === 404) {
        return {
          success: false,
          error: "API key management is not available yet.",
        };
      }
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to generate API key.",
          "api-key"
        ),
      };
    }
  },

  // Get user's API keys (enhanced)
  getApiKeys: async () => {
    try {
      const response = await api.get("/auth/api-keys/");
      return {
        success: true,
        data: response.data?.results || response.data || [],
      };
    } catch (error) {
      // If endpoint doesn't exist, return empty array
      if (error.response?.status === 404) {
        return { success: true, data: [] };
      }
      return {
        success: false,
        error: getEnhancedErrorMessage(
          error,
          "Failed to fetch API keys",
          "api-keys"
        ),
      };
    }
  },
};

// Export as a named export and as a default export to ensure compatibility
export { authService };
export default authService;
