// frontend/src/pages/auth/ForgotPassword.js

import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { authService } from "../../services/authService";

const ForgotPassword = () => {
  const location = useLocation();

  const [email, setEmail] = useState(location.state?.email || "");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!email.trim()) {
      setError("Please enter your email address");
      return;
    }

    setLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await authService.requestPasswordReset(email);

      if (response.success) {
        setSubmitted(true);
        setMessage(
          "Password reset instructions have been sent to your email address."
        );
      } else {
        setError(
          response.error ||
            "Failed to send password reset email. Please try again."
        );
      }
    } catch (error) {
      setError("An unexpected error occurred. Please try again.");
      console.error("Password reset error:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleResend = () => {
    setSubmitted(false);
    setMessage("");
    setError("");
  };

  if (submitted) {
    return (
      <div className="container py-5">
        <div className="row justify-content-center">
          <div className="col-md-6 col-lg-5">
            <div className="card shadow">
              <div className="card-body p-5 text-center">
                <div className="text-success mb-4">
                  <i
                    className="fas fa-check-circle"
                    style={{ fontSize: "4rem" }}
                  ></i>
                </div>

                <h2 className="mb-3">Check Your Email</h2>

                <div className="alert alert-success">{message}</div>

                <p className="text-muted mb-4">
                  We've sent password reset instructions to{" "}
                  <strong>{email}</strong>. Please check your inbox and spam
                  folder.
                </p>

                <div className="alert alert-info">
                  <div className="d-flex">
                    <i className="fas fa-info-circle me-2 mt-1 flex-shrink-0"></i>
                    <div>
                      <strong>Didn't receive the email?</strong>
                      <ul className="mb-0 mt-2 text-start">
                        <li>Check your spam/junk folder</li>
                        <li>Make sure the email address is correct</li>
                        <li>The link will expire in 1 hour for security</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="d-grid gap-2 mb-4">
                  <button
                    className="btn btn-outline-primary"
                    onClick={handleResend}
                  >
                    <i className="fas fa-paper-plane me-1"></i>
                    Send Another Email
                  </button>
                </div>

                <div className="text-center">
                  <Link to="/login" className="text-decoration-none">
                    <i className="fas fa-arrow-left me-1"></i>
                    Back to Login
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-5">
          <div className="card shadow">
            <div className="card-body p-5">
              <div className="text-center mb-4">
                <i
                  className="fas fa-key text-primary mb-3"
                  style={{ fontSize: "3rem" }}
                ></i>
                <h2>Forgot Password?</h2>
                <p className="text-muted">
                  No worries! Enter your email address and we'll send you reset
                  instructions.
                </p>
              </div>

              {error && (
                <div className="alert alert-danger" role="alert">
                  <i className="fas fa-exclamation-circle me-2"></i>
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit}>
                <div className="mb-4">
                  <label htmlFor="email" className="form-label">
                    Email address
                  </label>
                  <input
                    type="email"
                    className="form-control"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email address"
                    required
                    autoComplete="email"
                    autoFocus
                  />
                  <div className="form-text">
                    We'll send reset instructions to this email address
                  </div>
                </div>

                <div className="d-grid mb-4">
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Sending Instructions...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-paper-plane me-1"></i>
                        Send Reset Instructions
                      </>
                    )}
                  </button>
                </div>
              </form>

              <div className="text-center">
                <p className="mb-2">
                  <Link to="/login" className="text-decoration-none">
                    <i className="fas fa-arrow-left me-1"></i>
                    Back to Login
                  </Link>
                </p>
                <p className="mb-0">
                  Don't have an account?{" "}
                  <Link to="/register" className="text-decoration-none">
                    Create one
                  </Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
