// frontend/src/components/auth/EmailVerification.js

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { authService } from "../../services/authService";

const EmailVerification = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState("verifying");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");

  useEffect(() => {
    const verifyEmail = async () => {
      const token = searchParams.get("token");
      const uid = searchParams.get("uid");

      if (!token || !uid) {
        setStatus("error");
        setMessage(
          "Invalid verification link. Please check your email and try again."
        );
        return;
      }

      try {
        const result = await authService.verifyEmail(token, uid);

        if (result.success) {
          setStatus("success");
          setMessage(
            "Your email has been successfully verified! You can now sign in."
          );
          setTimeout(() => navigate("/login", { replace: true }), 3000);
        } else {
          setStatus("error");
          setMessage(
            result.error || "Email verification failed. Please try again."
          );
        }
      } catch (error) {
        setStatus("error");
        setMessage("An error occurred during verification. Please try again.");
      }
    };

    verifyEmail();
  }, [searchParams, navigate]);

  const handleResendVerification = async () => {
    if (!email) {
      setMessage("Please enter your email address to resend verification.");
      return;
    }

    try {
      const result = await authService.resendVerificationEmail(email);
      if (result.success) {
        setMessage(
          "Verification email has been resent. Please check your inbox."
        );
      } else {
        setMessage(result.error || "Failed to resend verification email.");
      }
    } catch (error) {
      setMessage("An error occurred. Please try again.");
    }
  };

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-5">
          <div className="card shadow">
            <div className="card-body text-center p-5">
              {status === "verifying" && (
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
                  <h4 className="mb-3">Verifying Your Email</h4>
                  <p className="text-muted">
                    Please wait while we verify your email address...
                  </p>
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
                  <h4 className="text-success mb-3">Email Verified!</h4>
                  <p className="text-muted mb-4">{message}</p>
                  <div className="d-flex align-items-center justify-content-center">
                    <div
                      className="spinner-border spinner-border-sm text-success me-2"
                      role="status"
                    >
                      <span className="visually-hidden">Loading...</span>
                    </div>
                    <small className="text-muted">
                      Redirecting to login...
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
                  <h4 className="text-danger mb-3">Verification Failed</h4>
                  <div className="alert alert-danger mb-4">{message}</div>

                  <div className="mb-4">
                    <h6 className="mb-3">Resend Verification Email</h6>
                    <div className="input-group mb-3">
                      <input
                        type="email"
                        className="form-control"
                        placeholder="Enter your email address"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                      />
                      <button
                        className="btn btn-outline-primary"
                        type="button"
                        onClick={handleResendVerification}
                      >
                        Resend
                      </button>
                    </div>
                  </div>

                  <div className="d-grid gap-2">
                    <button
                      className="btn btn-primary"
                      onClick={() => navigate("/login", { replace: true })}
                    >
                      <i className="fas fa-sign-in-alt me-1"></i>
                      Go to Login
                    </button>
                    <button
                      className="btn btn-outline-secondary"
                      onClick={() => navigate("/", { replace: true })}
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

export default EmailVerification;
