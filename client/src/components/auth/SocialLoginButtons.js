// frontend/src/components/auth/SocialLoginButtons.js - Enhanced with improvements

import { useCallback, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { socialAuthService } from "../../services/socialAuthService";

const SocialLoginButtons = ({ className = "" }) => {
  const { setSocialUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(null);
  const [error, setError] = useState("");
  const lastClickTimeRef = useRef(0);

  const from = location.state?.from?.pathname || "/dashboard";
  const availableProviders = socialAuthService.getAvailableProviders();

  // Enhanced error message mapping
  const getErrorMessage = (errorMsg) => {
    if (!errorMsg) return "An unexpected error occurred. Please try again.";

    const message = errorMsg.toLowerCase();

    if (
      message.includes("bad_verification_code") ||
      message.includes("expired")
    ) {
      return "The authorization code has expired. Please try signing in again.";
    }
    if (message.includes("access_denied")) {
      return "Access was denied. Please authorize the application and try again.";
    }
    if (message.includes("invalid_client")) {
      return "There's a configuration issue with this login method. Please try another method or contact support.";
    }
    if (message.includes("network error") || message.includes("timeout")) {
      return "Network connection issue. Please check your internet connection and try again.";
    }
    if (
      message.includes("email not provided") ||
      message.includes("no email")
    ) {
      return "Your email address is required. Please make sure your email is public in your account settings.";
    }
    if (
      message.includes("rate limit") ||
      message.includes("too many requests")
    ) {
      return "Too many login attempts. Please wait a moment and try again.";
    }
    if (
      message.includes("server error") ||
      message.includes("internal server error")
    ) {
      return "Server temporarily unavailable. Please try again in a few minutes.";
    }

    return errorMsg.length > 100
      ? errorMsg.substring(0, 100) + "..."
      : errorMsg;
  };

  // Debounce function to prevent rapid clicks
  const debounceClick = useCallback((callback, delay = 2000) => {
    const now = Date.now();
    if (now - lastClickTimeRef.current < delay) {
      return false; // Ignore rapid clicks
    }
    lastClickTimeRef.current = now;
    callback();
    return true;
  }, []);

  const handleSocialLogin = async (provider) => {
    // Prevent multiple clicks with debouncing
    const canProceed = debounceClick(() => {
      performLogin(provider);
    });

    if (!canProceed) {
      // Show brief feedback for ignored clicks
      setError("Please wait before trying again...");
      setTimeout(() => setError(""), 1500);
      return;
    }
  };

  const performLogin = async (provider) => {
    if (loading) return; // Prevent clicks while already loading

    setLoading(provider);
    setError("");

    try {
      let result;

      if (provider === "google") {
        result = await socialAuthService.loginWithGoogle();
      } else if (provider === "github") {
        // Store current location for redirect after OAuth
        localStorage.setItem("oauth_redirect", from);
        await socialAuthService.loginWithGitHub();
        return; // GitHub redirects, so we don't continue here
      } else if (provider === "microsoft") {
        // Store current location for redirect after OAuth
        localStorage.setItem("oauth_redirect", from);
        await socialAuthService.loginWithMicrosoft();
        return; // Microsoft redirects, so we don't continue here
      }

      if (result && result.success) {
        setSocialUser(result.user);
        navigate(from, { replace: true });
      } else {
        setError(getErrorMessage(result?.error));
      }
    } catch (error) {
      console.error("Social login error:", error);
      setError(socialAuthService.handleSocialAuthError(error, provider));
    } finally {
      // Reset loading state after a minimum time to prevent flickering
      setTimeout(() => setLoading(null), 500);
    }
  };

  // Clear error after some time
  const clearError = () => {
    setTimeout(() => setError(""), 5000);
  };

  if (availableProviders.length === 0) {
    return null;
  }

  return (
    <div className={`social-login-buttons ${className}`}>
      {error && (
        <div
          className="alert alert-danger alert-sm mb-3 d-flex align-items-center"
          role="alert"
        >
          <i className="fas fa-exclamation-triangle me-2"></i>
          <div className="flex-grow-1">{error}</div>
          <button
            type="button"
            className="btn-close btn-close-sm"
            aria-label="Close"
            onClick={() => setError("")}
          ></button>
        </div>
      )}

      <div className="text-center mb-3">
        <span className="text-muted small"></span>
      </div>

      <div className="d-grid gap-2">
        {availableProviders.map((provider) => {
          const isLoading = loading === provider.name;

          return (
            <button
              key={provider.name}
              type="button"
              className={`btn btn-outline-secondary d-flex align-items-center justify-content-center position-relative ${
                isLoading ? "disabled" : ""
              }`}
              onClick={() => handleSocialLogin(provider.name)}
              disabled={isLoading || loading !== null}
              style={{
                "--provider-color": provider.color,
                minHeight: "48px",
                transition: "all 0.2s ease",
              }}
              title={
                isLoading
                  ? "Connecting..."
                  : `Continue with ${provider.displayName}`
              }
            >
              {isLoading ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  <span>Connecting to {provider.displayName}...</span>
                </>
              ) : (
                <>
                  <i
                    className={`${provider.icon} me-2`}
                    style={{ color: provider.color }}
                  ></i>
                  <span>Continue with {provider.displayName}</span>
                </>
              )}
            </button>
          );
        })}
      </div>

      {/* Loading overlay for better UX */}
      {loading && (
        <div className="text-center mt-2">
          <small className="text-muted">
            <i className="fas fa-shield-alt me-1"></i>
            Securely connecting to{" "}
            {availableProviders.find((p) => p.name === loading)?.displayName}...
          </small>
        </div>
      )}

      <style jsx>{`
        .social-login-buttons .btn-outline-secondary:hover:not(:disabled) {
          background-color: var(--provider-color, #6c757d);
          border-color: var(--provider-color, #6c757d);
          color: white;
          transform: translateY(-1px);
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .social-login-buttons .btn-outline-secondary:hover:not(:disabled) i {
          color: white !important;
        }

        .social-login-buttons .btn-outline-secondary:disabled {
          opacity: 0.8;
          cursor: not-allowed;
        }

        .social-login-buttons .alert-sm {
          font-size: 0.875rem;
          padding: 0.5rem 0.75rem;
        }

        .social-login-buttons .btn-close-sm {
          font-size: 0.75rem;
          padding: 0.25rem;
        }
      `}</style>
    </div>
  );
};

export default SocialLoginButtons;
