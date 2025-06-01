// frontend/src/components/auth/EmailVerificationRequired.js

import { useState } from "react";
import { Link } from "react-router-dom";
import { authService } from "../../services/authService";

const EmailVerificationRequired = ({ email }) => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [resendCount, setResendCount] = useState(0);

  const handleResendEmail = async () => {
    if (resendCount >= 3) {
      setMessage(
        "Maximum resend attempts reached. Please contact support if you continue to have issues."
      );
      return;
    }

    setLoading(true);
    setMessage("");

    try {
      const result = await authService.resendVerificationEmail(email);

      if (result.success) {
        setMessage(
          "Verification email has been resent successfully! Please check your inbox and spam folder."
        );
        setResendCount((prev) => prev + 1);
      } else {
        setMessage(
          result.error ||
            "Failed to resend verification email. Please try again."
        );
      }
    } catch (error) {
      setMessage(
        "An error occurred while resending the email. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-8 col-lg-6">
          <div className="card shadow">
            <div className="card-body text-center p-5">
              <div className="text-warning mb-4">
                <i className="fas fa-envelope" style={{ fontSize: "4rem" }}></i>
              </div>

              <h3 className="mb-3">Please Verify Your Email</h3>

              <p className="text-muted mb-4">
                We've sent a verification email to <strong>{email}</strong>.
                Please check your inbox and click the verification link to
                activate your account.
              </p>

              <div className="alert alert-info">
                <div className="d-flex">
                  <i className="fas fa-info-circle me-2 mt-1 flex-shrink-0"></i>
                  <div>
                    <strong>Didn't receive the email?</strong>
                    <ul className="mb-0 mt-2 text-start">
                      <li>Check your spam/junk folder</li>
                      <li>Make sure the email address is correct</li>
                      <li>Add our domain to your safe senders list</li>
                    </ul>
                  </div>
                </div>
              </div>

              {message && (
                <div
                  className={`alert ${
                    message.includes("success")
                      ? "alert-success"
                      : "alert-warning"
                  } mb-4`}
                >
                  {message}
                </div>
              )}

              <div className="d-grid gap-2 mb-4">
                <button
                  className="btn btn-primary"
                  onClick={handleResendEmail}
                  disabled={loading || resendCount >= 3}
                >
                  {loading ? (
                    <>
                      <span
                        className="spinner-border spinner-border-sm me-2"
                        role="status"
                      ></span>
                      Sending...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-paper-plane me-1"></i>
                      Resend Verification Email
                      {resendCount > 0 && ` (${resendCount}/3)`}
                    </>
                  )}
                </button>
              </div>

              <div className="text-center">
                <p className="mb-2">
                  <Link to="/login" className="text-decoration-none">
                    <i className="fas fa-arrow-left me-1"></i>
                    Back to Login
                  </Link>
                </p>
                <p className="mb-0">
                  <Link to="/contact" className="text-decoration-none">
                    <i className="fas fa-question-circle me-1"></i>
                    Need help? Contact Support
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

export default EmailVerificationRequired;
