// frontend/src/services/socialAuthService.js - Enhanced with Microsoft support

import { clearTokens, setTokens } from "../utils/storage";
import api from "./api";

class SocialAuthService {
  constructor() {
    this.googleAuth = null;
    this.isGoogleInitialized = false;
    this.isMicrosoftInitialized = false;
    this.msalInstance = null;
  }

  // Initialize Google OAuth
  async initializeGoogle() {
    if (this.isGoogleInitialized) return this.googleAuth;

    try {
      await this.loadGoogleScript();

      this.googleAuth = window.google.accounts.oauth2.initTokenClient({
        client_id: process.env.REACT_APP_GOOGLE_CLIENT_ID,
        scope: "openid email profile",
        callback: (response) => {
          // This will be handled by the component
        },
      });

      this.isGoogleInitialized = true;
      return this.googleAuth;
    } catch (error) {
      console.error("Failed to initialize Google Auth:", error);
      throw error;
    }
  }

  // Load Google OAuth script
  loadGoogleScript() {
    return new Promise((resolve, reject) => {
      if (window.google && window.google.accounts) {
        resolve();
        return;
      }

      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;

      script.onload = () => resolve();
      script.onerror = () =>
        reject(new Error("Failed to load Google OAuth script"));

      document.head.appendChild(script);
    });
  }

  // Initialize Microsoft OAuth
  async initializeMicrosoft() {
    if (this.isMicrosoftInitialized && this.msalInstance) {
      return this.msalInstance;
    }

    try {
      await this.loadMicrosoftScript();

      const msalConfig = {
        auth: {
          clientId: process.env.REACT_APP_MICROSOFT_CLIENT_ID,
          authority: "https://login.microsoftonline.com/common",
          redirectUri: `${window.location.origin}/auth/microsoft/callback`,
        },
        cache: {
          cacheLocation: "sessionStorage",
          storeAuthStateInCookie: false,
        },
      };

      this.msalInstance = new window.msal.PublicClientApplication(msalConfig);
      await this.msalInstance.initialize();

      this.isMicrosoftInitialized = true;
      return this.msalInstance;
    } catch (error) {
      console.error("Failed to initialize Microsoft Auth:", error);
      throw error;
    }
  }

  // Load Microsoft MSAL script
  loadMicrosoftScript() {
    return new Promise((resolve, reject) => {
      if (window.msal) {
        resolve();
        return;
      }

      const script = document.createElement("script");
      script.src =
        "https://alcdn.msauth.net/browser/2.30.0/js/msal-browser.min.js";
      script.async = true;
      script.defer = true;

      script.onload = () => resolve();
      script.onerror = () =>
        reject(new Error("Failed to load Microsoft MSAL script"));

      document.head.appendChild(script);
    });
  }

  // Google OAuth login
  async loginWithGoogle() {
    try {
      await this.initializeGoogle();

      return new Promise((resolve, reject) => {
        this.googleAuth.callback = async (response) => {
          if (response.access_token) {
            try {
              const result = await this.exchangeTokenForJWT(
                "google-oauth2",
                response.access_token
              );
              resolve(result);
            } catch (error) {
              reject(error);
            }
          } else {
            reject(new Error("Failed to get access token from Google"));
          }
        };

        this.googleAuth.requestAccessToken();
      });
    } catch (error) {
      throw new Error(`Google authentication failed: ${error.message}`);
    }
  }

  // GitHub OAuth login
  async loginWithGitHub() {
    try {
      const clientId = process.env.REACT_APP_GITHUB_CLIENT_ID;
      if (!clientId) {
        throw new Error("GitHub OAuth is not configured");
      }

      const redirectUri = `${window.location.origin}/auth/github/callback`;
      const scope = "user:email";
      const state = this.generateState();

      // Store state for verification
      sessionStorage.setItem("github_oauth_state", state);

      const authUrl =
        `https://github.com/login/oauth/authorize?` +
        `client_id=${clientId}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `scope=${scope}&` +
        `state=${state}`;

      // Store the current location for redirect after auth
      localStorage.setItem("oauth_redirect", window.location.pathname);

      // Redirect to GitHub
      window.location.href = authUrl;
    } catch (error) {
      throw new Error(`GitHub authentication failed: ${error.message}`);
    }
  }

  // Microsoft OAuth login
  async loginWithMicrosoft() {
    try {
      const clientId = process.env.REACT_APP_MICROSOFT_CLIENT_ID;
      if (!clientId) {
        throw new Error("Microsoft OAuth is not configured");
      }

      // For direct redirect approach (simpler and more reliable)
      const redirectUri = `${window.location.origin}/auth/microsoft/callback`;
      const scope = "openid profile email";
      const state = this.generateState();

      // Store state and redirect path
      sessionStorage.setItem("microsoft_oauth_state", state);
      localStorage.setItem("oauth_redirect", window.location.pathname);

      const authUrl =
        `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` +
        `client_id=${clientId}&` +
        `response_type=code&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `scope=${encodeURIComponent(scope)}&` +
        `state=${state}&` +
        `response_mode=query`;

      // Redirect to Microsoft
      window.location.href = authUrl;
    } catch (error) {
      throw new Error(`Microsoft authentication failed: ${error.message}`);
    }
  }

  // Alternative Microsoft login using popup (if needed)
  async loginWithMicrosoftPopup() {
    try {
      await this.initializeMicrosoft();

      const loginRequest = {
        scopes: ["openid", "profile", "email"],
        prompt: "select_account",
      };

      // Initiate login popup
      const result = await this.msalInstance.loginPopup(loginRequest);

      if (result.accessToken) {
        // Exchange Microsoft token for our JWT
        return await this.exchangeTokenForJWT("microsoft", result.accessToken);
      }

      throw new Error("No access token received from Microsoft");
    } catch (error) {
      throw new Error(`Microsoft authentication failed: ${error.message}`);
    }
  }

  // Handle GitHub callback
  async handleGitHubCallback(code, state) {
    try {
      // Verify state parameter
      const storedState = sessionStorage.getItem("github_oauth_state");
      sessionStorage.removeItem("github_oauth_state");

      if (state !== storedState) {
        throw new Error("Invalid state parameter");
      }

      // Exchange code for access token via our backend
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
        throw new Error(response.data.error || "GitHub authentication failed");
      }
    } catch (error) {
      throw new Error(`GitHub callback handling failed: ${error.message}`);
    }
  }

  // Handle Microsoft callback
  async handleMicrosoftCallback(code, state) {
    try {
      // Verify state parameter
      const storedState = sessionStorage.getItem("microsoft_oauth_state");
      sessionStorage.removeItem("microsoft_oauth_state");

      if (state !== storedState) {
        throw new Error("Invalid state parameter");
      }

      // Exchange code for access token via our backend
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
        throw new Error(
          response.data.error || "Microsoft authentication failed"
        );
      }
    } catch (error) {
      throw new Error(`Microsoft callback handling failed: ${error.message}`);
    }
  }

  // Exchange social auth token for JWT
  async exchangeTokenForJWT(provider, accessToken) {
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
  }

  // Connect social account (for settings page)
  async connectSocialAccount(provider) {
    try {
      const response = await api.post("/auth/social/connect/", { provider });
      return { success: true, data: response.data };
    } catch (error) {
      // If endpoint doesn't exist, handle client-side
      if (error.response?.status === 404) {
        if (provider === "github") {
          await this.loginWithGitHub();
          return { success: true, data: { redirect: true } };
        } else if (provider === "microsoft") {
          await this.loginWithMicrosoft();
          return { success: true, data: { redirect: true } };
        }
      }
      return {
        success: false,
        error:
          error.response?.data?.error || "Failed to connect social account",
      };
    }
  }

  // Disconnect social account
  async disconnectSocialAccount(provider) {
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
  }

  // Generate random state for OAuth
  generateState() {
    return (
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15)
    );
  }

  // Verify OAuth state parameter for security
  verifyState(receivedState, provider) {
    const storedState = sessionStorage.getItem(`${provider}_oauth_state`);
    sessionStorage.removeItem(`${provider}_oauth_state`);
    return storedState === receivedState;
  }

  // Get available social providers
  getAvailableProviders() {
    const providers = [
      {
        name: "google",
        displayName: "Google",
        icon: "fab fa-google",
        color: "#db4437",
        enabled: !!process.env.REACT_APP_GOOGLE_CLIENT_ID,
      },
      {
        name: "github",
        displayName: "GitHub",
        icon: "fab fa-github",
        color: "#333",
        enabled: !!process.env.REACT_APP_GITHUB_CLIENT_ID,
      },
      {
        name: "microsoft",
        displayName: "Microsoft",
        icon: "fab fa-microsoft",
        color: "#0078d4",
        enabled: !!process.env.REACT_APP_MICROSOFT_CLIENT_ID,
      },
    ];

    return providers.filter((provider) => provider.enabled);
  }

  // Check if a specific provider is available
  isProviderAvailable(providerName) {
    return this.getAvailableProviders().some((p) => p.name === providerName);
  }

  // Get provider configuration
  getProviderConfig(providerName) {
    return this.getAvailableProviders().find((p) => p.name === providerName);
  }

  // Logout (clear all auth data)
  logout() {
    clearTokens();
    localStorage.removeItem("user");
    localStorage.removeItem("oauth_redirect");

    // Clear any OAuth states
    sessionStorage.removeItem("github_oauth_state");
    sessionStorage.removeItem("microsoft_oauth_state");
    sessionStorage.removeItem("google_oauth_state");

    // Clear processed codes
    sessionStorage.removeItem("github_oauth_processed");
    sessionStorage.removeItem("microsoft_oauth_processed");
  }

  // Enhanced error handling for social auth
  handleSocialAuthError(error, provider) {
    console.error(`${provider} authentication error:`, error);

    let userMessage = `${provider} authentication failed.`;

    if (error.message?.includes("popup_closed")) {
      userMessage = "Authentication was cancelled. Please try again.";
    } else if (error.message?.includes("network")) {
      userMessage =
        "Network error. Please check your connection and try again.";
    } else if (error.message?.includes("not configured")) {
      userMessage = `${provider} authentication is not configured.`;
    }

    return userMessage;
  }
}

export const socialAuthService = new SocialAuthService();
export default socialAuthService;
