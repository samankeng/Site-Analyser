// frontend/src/pages/auth/Register.js - Fixed to remove username field

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import SocialLoginButtons from "../../components/auth/SocialLoginButtons";
import { authService } from "../../services/authService";

const Register = () => {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: "",
    password: "",
    password_confirm: "",
    first_name: "",
    last_name: "",
    company: "",
    job_title: "",
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");
    setFieldErrors({});

    try {
      const response = await authService.register(formData);

      if (response.success) {
        // Always redirect to login with verification message
        navigate("/login", {
          state: {
            message:
              "Registration successful! Please check your email to verify your account before signing in.",
            email: formData.email,
            showEmailVerification: true,
          },
        });
      } else {
        // Handle validation errors
        if (typeof response.error === "object") {
          // Check if it's an email already exists error
          if (response.error.email) {
            const emailError = Array.isArray(response.error.email)
              ? response.error.email[0]
              : response.error.email;

            // Convert to string if it's an ErrorDetail object
            const emailErrorString =
              typeof emailError === "string"
                ? emailError
                : emailError.toString();

            if (
              emailErrorString.toLowerCase().includes("already exists") ||
              emailErrorString.toLowerCase().includes("user with this email")
            ) {
              // Redirect to login page with message about existing email
              navigate("/login", {
                state: {
                  message:
                    "An account with this email already exists. Please sign in instead.",
                  email: formData.email,
                  type: "info",
                },
              });
              return;
            }
          }
          setFieldErrors(response.error);
        } else {
          setError(response.error || "Registration failed. Please try again.");
        }
      }
    } catch (error) {
      setError("An unexpected error occurred. Please try again.");
      console.error("Registration error:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-8 col-lg-6">
          <div className="card shadow">
            <div className="card-body p-5">
              <h2 className="text-center mb-4">Create Your Account</h2>

              {error && (
                <div className="alert alert-danger" role="alert">
                  {error}
                </div>
              )}

              {/* Social Login Buttons */}
              <SocialLoginButtons className="mb-4" />

              {/* Divider */}
              <div className="position-relative mb-4">
                <hr />
                <span className="position-absolute top-50 start-50 translate-middle bg-white px-3 text-muted small">
                  Or create account with email
                </span>
              </div>

              {/* Registration Form */}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">
                    Email address *
                  </label>
                  <input
                    type="email"
                    className={`form-control ${
                      fieldErrors.email ? "is-invalid" : ""
                    }`}
                    id="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    required
                    autoComplete="email"
                    placeholder="Enter your email address"
                  />
                  {fieldErrors.email && (
                    <div className="invalid-feedback">
                      {Array.isArray(fieldErrors.email)
                        ? fieldErrors.email.join(", ")
                        : fieldErrors.email}
                    </div>
                  )}
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="password" className="form-label">
                      Password *
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
                      required
                      autoComplete="new-password"
                      placeholder="Enter password"
                    />
                    {fieldErrors.password && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.password)
                          ? fieldErrors.password.join(", ")
                          : fieldErrors.password}
                      </div>
                    )}
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="password_confirm" className="form-label">
                      Confirm Password *
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
                      required
                      autoComplete="new-password"
                      placeholder="Confirm password"
                    />
                    {fieldErrors.password_confirm && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.password_confirm)
                          ? fieldErrors.password_confirm.join(", ")
                          : fieldErrors.password_confirm}
                      </div>
                    )}
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="first_name" className="form-label">
                      First Name
                    </label>
                    <input
                      type="text"
                      className={`form-control ${
                        fieldErrors.first_name ? "is-invalid" : ""
                      }`}
                      id="first_name"
                      name="first_name"
                      value={formData.first_name}
                      onChange={handleChange}
                      autoComplete="given-name"
                      placeholder="Enter first name"
                    />
                    {fieldErrors.first_name && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.first_name)
                          ? fieldErrors.first_name.join(", ")
                          : fieldErrors.first_name}
                      </div>
                    )}
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="last_name" className="form-label">
                      Last Name
                    </label>
                    <input
                      type="text"
                      className={`form-control ${
                        fieldErrors.last_name ? "is-invalid" : ""
                      }`}
                      id="last_name"
                      name="last_name"
                      value={formData.last_name}
                      onChange={handleChange}
                      autoComplete="family-name"
                      placeholder="Enter last name"
                    />
                    {fieldErrors.last_name && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.last_name)
                          ? fieldErrors.last_name.join(", ")
                          : fieldErrors.last_name}
                      </div>
                    )}
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="company" className="form-label">
                      Company
                    </label>
                    <input
                      type="text"
                      className={`form-control ${
                        fieldErrors.company ? "is-invalid" : ""
                      }`}
                      id="company"
                      name="company"
                      value={formData.company}
                      onChange={handleChange}
                      autoComplete="organization"
                      placeholder="Enter company name"
                    />
                    {fieldErrors.company && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.company)
                          ? fieldErrors.company.join(", ")
                          : fieldErrors.company}
                      </div>
                    )}
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="job_title" className="form-label">
                      Job Title
                    </label>
                    <input
                      type="text"
                      className={`form-control ${
                        fieldErrors.job_title ? "is-invalid" : ""
                      }`}
                      id="job_title"
                      name="job_title"
                      value={formData.job_title}
                      onChange={handleChange}
                      autoComplete="organization-title"
                      placeholder="Enter job title"
                    />
                    {fieldErrors.job_title && (
                      <div className="invalid-feedback">
                        {Array.isArray(fieldErrors.job_title)
                          ? fieldErrors.job_title.join(", ")
                          : fieldErrors.job_title}
                      </div>
                    )}
                  </div>
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="terms"
                    required
                  />
                  <label className="form-check-label" htmlFor="terms">
                    I agree to the{" "}
                    <Link to="/terms" target="_blank">
                      Terms of Service
                    </Link>{" "}
                    and{" "}
                    <Link to="/privacy" target="_blank">
                      Privacy Policy
                    </Link>
                  </label>
                </div>

                <div className="d-grid mt-4">
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
                        Creating Account...
                      </>
                    ) : (
                      "Create Account"
                    )}
                  </button>
                </div>
              </form>

              <div className="text-center mt-4">
                <p>
                  Already have an account?{" "}
                  <Link to="/login" className="text-decoration-none">
                    Sign in
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

export default Register;
