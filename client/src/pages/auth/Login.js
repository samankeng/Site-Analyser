// frontend/src/pages/auth/Login.js - Enhanced with message handling

import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import SocialLoginButtons from "../../components/auth/SocialLoginButtons";
import { authService } from "../../services/authService";

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const [formData, setFormData] = useState({
    email: location.state?.email || "", // Pre-fill email if provided
    password: "",
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState("info"); // info, success, warning

  // Handle messages from navigation state
  useEffect(() => {
    if (location.state?.message) {
      setMessage(location.state.message);
      setMessageType(location.state.type || "info");

      // Clear the state to prevent message from persisting on refresh
      window.history.replaceState({}, document.title);
    }
  }, [location]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });

    // Clear error when user starts typing
    if (error) setError("");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await authService.login(
        formData.email,
        formData.password
      );

      if (response.success) {
        // Successful login
        navigate("/dashboard", { replace: true });
      } else {
        setError(
          response.error || "Login failed. Please check your credentials."
        );
      }
    } catch (error) {
      setError("An unexpected error occurred. Please try again.");
      console.error("Login error:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = () => {
    navigate("/auth/forgot-password", {
      state: { email: formData.email },
    });
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-5">
          <div className="card shadow">
            <div className="card-body p-5">
              <h2 className="text-center mb-4">Sign In</h2>

              {/* Display messages from navigation */}
              {message && (
                <div
                  className={`alert alert-${
                    messageType === "info"
                      ? "info"
                      : messageType === "success"
                      ? "success"
                      : "warning"
                  } alert-dismissible fade show`}
                  role="alert"
                >
                  <i
                    className={`fas ${
                      messageType === "info"
                        ? "fa-info-circle"
                        : messageType === "success"
                        ? "fa-check-circle"
                        : "fa-exclamation-triangle"
                    } me-2`}
                  ></i>
                  {message}
                  <button
                    type="button"
                    className="btn-close"
                    onClick={() => setMessage("")}
                    aria-label="Close"
                  ></button>
                </div>
              )}

              {/* Display login errors */}
              {error && (
                <div className="alert alert-danger" role="alert">
                  <i className="fas fa-exclamation-circle me-2"></i>
                  {error}
                </div>
              )}

              {/* Social Login Buttons */}
              <SocialLoginButtons className="mb-4" />

              {/* Divider */}
              <div className="position-relative mb-4">
                <hr />
                <span className="position-absolute top-50 start-50 translate-middle bg-white px-3 text-muted small">
                  Or sign in with email
                </span>
              </div>

              {/* Login Form */}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">
                    Email address
                  </label>
                  <input
                    type="email"
                    className="form-control"
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    required
                    autoComplete="email"
                    placeholder="Enter your email"
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="password" className="form-label">
                    Password
                  </label>
                  <input
                    type="password"
                    className="form-control"
                    id="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    autoComplete="current-password"
                    placeholder="Enter your password"
                  />
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="remember"
                  />
                  <label className="form-check-label" htmlFor="remember">
                    Remember me
                  </label>
                </div>

                <div className="d-grid">
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
                        Signing In...
                      </>
                    ) : (
                      "Sign In"
                    )}
                  </button>
                </div>
              </form>

              <div className="text-center mt-4">
                <p>
                  <button
                    type="button"
                    className="btn btn-link text-decoration-none p-0"
                    onClick={handleForgotPassword}
                  >
                    Forgot your password?
                  </button>
                </p>
                <p>
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

export default Login;
