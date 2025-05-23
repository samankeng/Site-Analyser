// frontend/src/components/auth/GitHubCallback.js

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { authService } from "../../services/authService";

const GitHubCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setSocialUser } = useAuth();
  const [status, setStatus] = useState("processing");
  const [error, setError] = useState("");

  useEffect(() => {
    const handleCallback = async () => {
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const error = searchParams.get("error");

      if (error) {
        setStatus("error");
        setError("GitHub authentication was cancelled or failed");
        setTimeout(() => navigate("/login"), 3000);
        return;
      }

      if (!code) {
        setStatus("error");
        setError("No authorization code received from GitHub");
        setTimeout(() => navigate("/login"), 3000);
        return;
      }

      try {
        // Use the authService to exchange GitHub code for JWT tokens
        const result = await authService.exchangeGitHubCode(code, state);

        if (result.success) {
          setSocialUser(result.user);
          setStatus("success");

          // Redirect to intended destination or dashboard
          const redirectPath =
            localStorage.getItem("oauth_redirect") || "/dashboard";
          localStorage.removeItem("oauth_redirect");

          setTimeout(() => navigate(redirectPath, { replace: true }), 1000);
        } else {
          throw new Error(result.error || "Authentication failed");
        }
      } catch (error) {
        setStatus("error");
        setError(error.message || "Authentication failed");
        setTimeout(() => navigate("/login"), 3000);
      }
    };

    handleCallback();
  }, [searchParams, navigate, setSocialUser]);

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow">
            <div className="card-body text-center p-5">
              {status === "processing" && (
                <>
                  <div
                    className="spinner-border text-primary mb-3"
                    role="status"
                  >
                    <span className="visually-hidden">Loading...</span>
                  </div>
                  <h4>Completing GitHub Authentication</h4>
                  <p className="text-muted">
                    Please wait while we process your login...
                  </p>
                </>
              )}

              {status === "success" && (
                <>
                  <div className="text-success mb-3">
                    <i className="fas fa-check-circle fa-3x"></i>
                  </div>
                  <h4 className="text-success">Authentication Successful!</h4>
                  <p className="text-muted">
                    Redirecting you to the dashboard...
                  </p>
                </>
              )}

              {status === "error" && (
                <>
                  <div className="text-danger mb-3">
                    <i className="fas fa-exclamation-circle fa-3x"></i>
                  </div>
                  <h4 className="text-danger">Authentication Failed</h4>
                  <p className="text-muted mb-3">{error}</p>
                  <p className="small text-muted">
                    Redirecting to login page...
                  </p>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GitHubCallback;
