// frontend/src/pages/auth/ResetPassword.js

import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { authService } from "../../services/authService";

const ResetPassword = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    password: "",
    password_confirm: "",
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const [isValidToken, setIsValidToken] = useState(true);

  const token = searchParams.get("token");
  const uid = searchParams.get("uid");

  useEffect(() => {
    // Check if we have required URL parameters
    if (!token || !uid) {
      setIsValidToken(false);
      setError(
        "Invalid password reset link. Please request a new password reset."
      );
    }
  }, [token, uid]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });

    // Clear field errors when user starts typing
    if (fieldErrors[name]) {
      setFieldErrors({ ...fieldErrors, [name]: "" });
    }
    if (error) setError("");
  };

  const validateForm = () => {
    const errors = {};

    if (!formData.password) {
      errors.password = "Password is required";
    } else if (formData.password.length < 8) {
      errors.password = "Password must be at least 8 characters long";
    }

    if (!formData.password_confirm) {
      errors.password_confirm = "Please confirm your password";
    } else if (formData.password !== formData.password_confirm) {
      errors.password_confirm = "Passwords do not match";
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await authService.confirmPasswordReset(
        token,
        uid,
        formData.password
      );

      if (response.success) {
        // Redirect to login with success message
        navigate("/login", {
          state: {
            message:
              "Your password has been reset successfully. Please sign in with your new password.",
            type: "success",
          },
        });
      } else {
        if (typeof response.error === "object") {
          setFieldErrors(response.error);
        } else {
          setError(
            response.error || "Failed to reset password. Please try again."
          );
        }
      }
    } catch (error) {
      setError("An unexpected error occurred. Please try again.");
      console.error("Password reset error:", error);
    } finally {
      setLoading(false);
    }
  };

  if (!isValidToken) {
    return (
      <div className="container py-5">
        <div className="row justify-content-center">
          <div className="col-md-6 col-lg-5">
            <div className="card shadow">
              <div className="card-body p-5 text-center">
                <div className="text-danger mb-4">
                  <i
                    className="fas fa-exclamation-triangle"
                    style={{ fontSize: "4rem" }}
                  ></i>
                </div>

                <h2 className="text-danger mb-3">Invalid Reset Link</h2>

                <div className="alert alert-danger">
                  This password reset link is invalid or has expired.
                </div>

                <p className="text-muted mb-4">
                  Password reset links expire after 1 hour for security reasons.
                  Please request a new password reset.
                </p>

                <div className="d-grid gap-2 mb-4">
                  <Link to="/auth/forgot-password" className="btn btn-primary">
                    <i className="fas fa-key me-1"></i>
                    Request New Reset Link
                  </Link>
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
                  className="fas fa-lock text-primary mb-3"
                  style={{ fontSize: "3rem" }}
                ></i>
                <h2>Reset Your Password</h2>
                <p className="text-muted">Enter your new password below</p>
              </div>

              {error && (
                <div className="alert alert-danger" role="alert">
                  <i className="fas fa-exclamation-circle me-2"></i>
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="password" className="form-label">
                    New Password
                  </label>
                  <input
                    type="password"
                    className={`form-control ${
                      fieldErrors.password ? "is-invalid" : ""
                    }`}
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="Enter your new password"
                    required
                    autoComplete="new-password"
                    autoFocus
                  />
                  {fieldErrors.password && (
                    <div className="invalid-feedback">
                      {fieldErrors.password}
                    </div>
                  )}
                  <div className="form-text">
                    Password must be at least 8 characters long
                  </div>
                </div>

                <div className="mb-4">
                  <label htmlFor="password_confirm" className="form-label">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    className={`form-control ${
                      fieldErrors.password_confirm ? "is-invalid" : ""
                    }`}
                    id="password_confirm"
                    name="password_confirm"
                    value={formData.password_confirm}
                    onChange={handleChange}
                    placeholder="Confirm your new password"
                    required
                    autoComplete="new-password"
                  />
                  {fieldErrors.password_confirm && (
                    <div className="invalid-feedback">
                      {fieldErrors.password_confirm}
                    </div>
                  )}
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
                        Resetting Password...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-check me-1"></i>
                        Reset Password
                      </>
                    )}
                  </button>
                </div>
              </form>

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
};

export default ResetPassword;
