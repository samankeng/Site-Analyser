// frontend/src/components/auth/MicrosoftCallback.js

import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";
import { authService } from "../../services/authService";

const MicrosoftCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setSocialUser } = useAuth();
  const [status, setStatus] = useState("processing");
  const [error, setError] = useState("");
  const [countdown, setCountdown] = useState(3);
  const exchangeAttempted = useRef(false);
  const countdownInterval = useRef(null);

  const getErrorMessage = (errorMsg, errorType) => {
    if (!errorMsg)
      return "Microsoft authentication failed for an unknown reason.";

    const message = errorMsg.toLowerCase();

    if (errorType === "user_cancelled") {
      return "Microsoft authentication was cancelled. You can try again or use a different login method.";
    }

    if (
      message.includes("invalid_request") ||
      message.includes("invalid_grant")
    ) {
      return "The authorization request was invalid. Please try logging in again.";
    }

    if (message.includes("access_denied")) {
      return "Access was denied during Microsoft authentication. Please authorize the application.";
    }

    if (message.includes("invalid_client")) {
      return "There's a configuration issue with Microsoft authentication. Please contact support.";
    }

    if (message.includes("network error") || message.includes("timeout")) {
      return "Network connection issue occurred during authentication. Please check your internet connection.";
    }

    if (
      message.includes("email not provided") ||
      message.includes("no email")
    ) {
      return "Your Microsoft email address is required but not accessible.";
    }

    if (message.includes("rate limit")) {
      return "Too many authentication attempts. Please wait a few minutes before trying again.";
    }

    return errorMsg.length > 150
      ? errorMsg.substring(0, 150) + "..."
      : errorMsg;
  };

  useEffect(() => {
    const startCountdown = () => {
      countdownInterval.current = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(countdownInterval.current);
            navigate("/login", { replace: true });
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    };

    const handleCallback = async () => {
      if (exchangeAttempted.current) {
        return;
      }

      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const oauthError = searchParams.get("error");
      const errorDescription = searchParams.get("error_description");

      // Check if we've already processed this code
      const processedCode = sessionStorage.getItem("microsoft_oauth_processed");
      if (processedCode === code) {
        setStatus("error");
        setError(
          "This authorization code has already been used. Please try logging in again."
        );
        startCountdown();
        return;
      }

      // Handle OAuth errors from Microsoft
      if (oauthError) {
        setStatus("error");
        let errorMessage = "Microsoft authentication failed";

        if (oauthError === "access_denied") {
          errorMessage = "You cancelled the Microsoft authentication";
        } else if (oauthError === "user_cancelled") {
          errorMessage = "Authentication was cancelled";
        } else if (errorDescription) {
          errorMessage = errorDescription;
        }

        setError(getErrorMessage(errorMessage, oauthError));
        startCountdown();
        return;
      }

      // Check for authorization code
      if (!code) {
        setStatus("error");
        setError(
          getErrorMessage("No authorization code received from Microsoft")
        );
        startCountdown();
        return;
      }

      // Mark that we're attempting the exchange
      exchangeAttempted.current = true;
      sessionStorage.setItem("microsoft_oauth_processed", code);

      try {
        // Use the authService to exchange Microsoft code for JWT tokens
        const result = await authService.exchangeMicrosoftCode(code, state);

        if (result && result.success) {
          setSocialUser(result.user);
          setStatus("success");

          // Clear the processed code on success
          sessionStorage.removeItem("microsoft_oauth_processed");

          // Get redirect path and clean up
          const redirectPath =
            localStorage.getItem("oauth_redirect") || "/dashboard";
          localStorage.removeItem("oauth_redirect");

          // Redirect after a brief success message
          setTimeout(() => navigate(redirectPath, { replace: true }), 1500);
        } else {
          throw new Error(result?.error || "Authentication failed");
        }
      } catch (error) {
        console.error("Microsoft OAuth callback error:", error);
        setStatus("error");
        setError(getErrorMessage(error.message));
        startCountdown();
      }
    };

    handleCallback();

    return () => {
      if (countdownInterval.current) {
        clearInterval(countdownInterval.current);
      }
    };
  }, [searchParams, navigate, setSocialUser]);

  const handleRetry = () => {
    sessionStorage.removeItem("microsoft_oauth_processed");
    navigate("/login", { replace: true });
  };

  const handleGoHome = () => {
    navigate("/", { replace: true });
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-8 col-lg-6">
          <div className="card shadow">
            <div className="card-body text-center p-5">
              {status === "processing" && (
                <>
                  <div className="mb-4">
                    <div
                      className="spinner-border text-primary"
                      style={{ width: "3rem", height: "3rem" }}
                      role="status"
                    >
                      <span className="visually-hidden">Loading...</span>
                    </div>
                  </div>
                  <h4 className="mb-3">Completing Microsoft Authentication</h4>
                  <p className="text-muted mb-0">
                    Please wait while we securely process your login...
                  </p>
                  <div className="mt-3">
                    <small className="text-muted">
                      <i className="fas fa-shield-alt me-1"></i>
                      This may take a few seconds
                    </small>
                  </div>
                </>
              )}

              {status === "success" && (
                <>
                  <div className="text-success mb-4">
                    <i
                      className="fas fa-check-circle"
                      style={{ fontSize: "4rem" }}
                    ></i>
                  </div>
                  <h4 className="text-success mb-3">
                    Authentication Successful!
                  </h4>
                  <p className="text-muted mb-3">
                    Welcome! You've been successfully authenticated with
                    Microsoft.
                  </p>
                  <div className="d-flex align-items-center justify-content-center">
                    <div
                      className="spinner-border spinner-border-sm text-success me-2"
                      role="status"
                    >
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <small className="text-muted">
                      Redirecting you to the dashboard...
                    </small>
                  </div>
                </>
              )}

              {status === "error" && (
                <>
                  <div className="text-danger mb-4">
                    <i
                      className="fas fa-exclamation-circle"
                      style={{ fontSize: "4rem" }}
                    ></i>
                  </div>
                  <h4 className="text-danger mb-3">Authentication Failed</h4>
                  <div className="alert alert-danger text-start mb-4">
                    <div className="d-flex">
                      <i className="fas fa-info-circle me-2 mt-1 flex-shrink-0"></i>
                      <div>{error}</div>
                    </div>
                  </div>

                  <div className="mb-4">
                    <p className="text-muted mb-2">
                      Redirecting to login page in <strong>{countdown}</strong>{" "}
                      seconds...
                    </p>
                    <div className="progress" style={{ height: "4px" }}>
                      <div
                        className="progress-bar"
                        role="progressbar"
                        style={{ width: `${((3 - countdown) / 3) * 100}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="d-grid gap-2 d-md-flex justify-content-md-center">
                    <button
                      className="btn btn-primary me-md-2"
                      onClick={handleRetry}
                    >
                      <i className="fas fa-redo me-1"></i>
                      Try Again
                    </button>
                    <button
                      className="btn btn-outline-secondary"
                      onClick={handleGoHome}
                    >
                      <i className="fas fa-home me-1"></i>
                      Go Home
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MicrosoftCallback;
