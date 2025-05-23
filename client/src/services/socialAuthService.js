// frontend/src/services/socialAuthService.js

import { clearTokens, setTokens } from "../utils/storage";
import api from "./api";

class SocialAuthService {
  constructor() {
    this.googleAuth = null;
    this.isGoogleInitialized = false;
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
      const redirectUri = `${window.location.origin}/auth/github/callback`;
      const scope = "user:email";

      const authUrl =
        `https://github.com/login/oauth/authorize?` +
        `client_id=${clientId}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `scope=${scope}&` +
        `state=${this.generateState()}`;

      // Store the current location for redirect after auth
      localStorage.setItem("oauth_redirect", window.location.pathname);

      // Redirect to GitHub
      window.location.href = authUrl;
    } catch (error) {
      throw new Error(`GitHub authentication failed: ${error.message}`);
    }
  }

  // Handle GitHub callback
  async handleGitHubCallback(code, state) {
    try {
      // Exchange code for access token
      const tokenResponse = await fetch("/api/auth/github/token/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code, state }),
      });

      if (!tokenResponse.ok) {
        throw new Error("Failed to exchange GitHub code for token");
      }

      const tokenData = await tokenResponse.json();

      // Exchange access token for JWT
      return await this.exchangeTokenForJWT("github", tokenData.access_token);
    } catch (error) {
      throw new Error(`GitHub callback handling failed: ${error.message}`);
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

  // Get available social providers
  getAvailableProviders() {
    return [
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
    ].filter((provider) => provider.enabled);
  }

  // Logout (clear all auth data)
  logout() {
    clearTokens();
    localStorage.removeItem("user");
    localStorage.removeItem("oauth_redirect");
  }
}

export const socialAuthService = new SocialAuthService();
export default socialAuthService;
