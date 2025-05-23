// frontend/src/components/auth/SocialLoginButtons.js

import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { socialAuthService } from "../../services/socialAuthService";

const SocialLoginButtons = ({ className = "" }) => {
  const { setSocialUser } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(null);
  const [error, setError] = useState("");

  const from = location.state?.from?.pathname || "/dashboard";
  const availableProviders = socialAuthService.getAvailableProviders();

  const handleSocialLogin = async (provider) => {
    setLoading(provider);
    setError("");

    try {
      let result;

      if (provider === "google") {
        result = await socialAuthService.loginWithGoogle();
      } else if (provider === "github") {
        await socialAuthService.loginWithGitHub();
        return; // GitHub redirects, so we don't continue here
      }

      if (result && result.success) {
        setSocialUser(result.user);
        navigate(from, { replace: true });
      } else {
        setError(result.error || "Social login failed");
      }
    } catch (error) {
      setError(error.message || "Social login failed");
      console.error("Social login error:", error);
    } finally {
      setLoading(null);
    }
  };

  if (availableProviders.length === 0) {
    return null;
  }

  return (
    <div className={`social-login-buttons ${className}`}>
      {error && (
        <div className="alert alert-danger alert-sm mb-3" role="alert">
          {error}
        </div>
      )}

      <div className="text-center mb-3">
        <span className="text-muted small">Or continue with</span>
      </div>

      <div className="d-grid gap-2">
        {availableProviders.map((provider) => (
          <button
            key={provider.name}
            type="button"
            className={`btn btn-outline-secondary d-flex align-items-center justify-content-center ${
              loading === provider.name ? "disabled" : ""
            }`}
            onClick={() => handleSocialLogin(provider.name)}
            disabled={loading === provider.name}
            style={{
              "--provider-color": provider.color,
            }}
          >
            {loading === provider.name ? (
              <>
                <span
                  className="spinner-border spinner-border-sm me-2"
                  role="status"
                  aria-hidden="true"
                ></span>
                Connecting...
              </>
            ) : (
              <>
                <i
                  className={`${provider.icon} me-2`}
                  style={{ color: provider.color }}
                ></i>
                Continue with {provider.displayName}
              </>
            )}
          </button>
        ))}
      </div>

      <style jsx>{`
        .social-login-buttons .btn-outline-secondary:hover {
          background-color: var(--provider-color, #6c757d);
          border-color: var(--provider-color, #6c757d);
          color: white;
        }

        .social-login-buttons .btn-outline-secondary:hover i {
          color: white !important;
        }
      `}</style>
    </div>
  );
};

export default SocialLoginButtons;
