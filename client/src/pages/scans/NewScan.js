// frontend/src/pages/scans/NewScan.js - FIXED VERSION

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ComplianceAcceptance from "../../components/compliance/ComplianceAcceptance";
import ScanForm from "../../components/security/ScanForm";
import { checkComplianceStatus } from "../../services/api";

const NewScan = () => {
  const [complianceStatus, setComplianceStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkUserCompliance();
  }, []);

  const checkUserCompliance = async () => {
    try {
      setLoading(true);
      setError(null); // Clear any previous errors
      const response = await checkComplianceStatus();
      setComplianceStatus(response);
    } catch (err) {
      console.error("Error checking compliance:", err);
      setError("Failed to check compliance status: " + err.message);
      setComplianceStatus(null); // Ensure it's null on error
    } finally {
      setLoading(false);
    }
  };

  const handleComplianceComplete = () => {
    // Refresh compliance status after user accepts agreements
    checkUserCompliance();
  };

  if (loading) {
    return (
      <div className="container py-4">
        <div className="d-flex justify-content-center">
          <div className="spinner-border" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container py-4">
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h2>New Security Scan</h2>
          <Link to="/dashboard" className="btn btn-outline-secondary">
            Back to Dashboard
          </Link>
        </div>

        <div className="alert alert-danger" role="alert">
          <h5 className="alert-heading">
            <i className="fas fa-exclamation-triangle me-2"></i>
            System Error
          </h5>
          <p>{error}</p>
          <hr />
          <p className="mb-0">
            <button
              className="btn btn-outline-danger btn-sm"
              onClick={checkUserCompliance}
            >
              <i className="fas fa-redo me-1"></i>
              Retry
            </button>
          </p>
        </div>
      </div>
    );
  }

  // FIXED: Check if complianceStatus exists AND agreements not accepted
  if (
    !complianceStatus ||
    (complianceStatus && !complianceStatus.all_agreements_accepted)
  ) {
    return (
      <div className="container py-4">
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h2>Legal Compliance Required</h2>
          <Link to="/dashboard" className="btn btn-outline-secondary">
            Back to Dashboard
          </Link>
        </div>

        <div className="row">
          <div className="col-lg-8 mx-auto">
            <div className="alert alert-info mb-4">
              <h5 className="alert-heading">
                <i className="fas fa-info-circle me-2"></i>
                Compliance Check Required
              </h5>
              <p className="mb-0">
                Before you can perform security scans, you must accept our legal
                agreements. This ensures responsible use of our scanning service
                and protects both you and us.
              </p>
            </div>

            <ComplianceAcceptance
              onComplianceComplete={handleComplianceComplete}
              missingAgreements={complianceStatus?.missing_agreements || []}
            />
          </div>
        </div>
      </div>
    );
  }

  // User has accepted all agreements, show the scan form
  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>New Security Scan</h2>
        <Link to="/dashboard" className="btn btn-outline-secondary">
          Back to Dashboard
        </Link>
      </div>

      {/* Compliance Status Indicator */}
      <div className="alert alert-success mb-4">
        <div className="d-flex align-items-center">
          <i className="fas fa-check-circle text-success me-2"></i>
          <span>
            <strong>Compliance Status:</strong> All legal agreements accepted.
            You can now perform security scans.
          </span>
        </div>
      </div>

      <div className="row">
        <div className="col-lg-8">
          <ScanForm />
        </div>

        <div className="col-lg-4">
          <div className="card shadow-sm">
            <div className="card-body">
              <h5 className="card-title">Scan Types</h5>

              <div className="mt-3">
                <h6>HTTP Headers Analysis</h6>
                <p className="text-muted small">
                  Examines HTTP headers for missing security headers such as
                  Content-Security-Policy, X-Frame-Options, and
                  Strict-Transport-Security.
                </p>
              </div>

              <div className="mt-3">
                <h6>SSL/TLS Configuration</h6>
                <p className="text-muted small">
                  Checks SSL/TLS certificate validity, protocol versions, and
                  cipher suites to identify potential vulnerabilities.
                </p>
              </div>

              <div className="mt-3">
                <h6>Vulnerability Scan</h6>
                <p className="text-muted small">
                  Detects common web vulnerabilities such as exposed sensitive
                  files, outdated software versions, and security
                  misconfigurations.
                </p>
              </div>

              <div className="mt-3">
                <h6>Content Analysis</h6>
                <p className="text-muted small">
                  Analyzes page content for SEO issues, accessibility problems,
                  and potential information disclosure risks.
                </p>
              </div>

              <div className="mt-3">
                <h6>Port Scanning</h6>
                <p className="text-muted small">
                  Identifies open ports and services that could potentially
                  expose your infrastructure to attackers.
                </p>
              </div>

              <div className="mt-3">
                <h6>Content Security Policy</h6>
                <p className="text-muted small">
                  Evaluates your CSP implementation to ensure proper protection
                  against cross-site scripting (XSS) and other code injection
                  attacks.
                </p>
              </div>
            </div>
          </div>

          {/* Compliance & Authorization Info */}
          <div className="card shadow-sm mt-3">
            <div className="card-body">
              <h5 className="card-title">Legal & Compliance</h5>

              <div className="mt-3">
                <h6>Domain Authorization</h6>
                <p className="text-muted small">
                  For scanning your own websites, you'll need to request domain
                  authorization. Self-owned domains are automatically approved.
                </p>
              </div>

              <div className="mt-3">
                <h6>Development Domains</h6>
                <p className="text-muted small">
                  Testing domains like badssl.com, localhost, and demo sites
                  don't require special authorization.
                </p>
              </div>

              <div className="mt-3">
                <Link
                  to="/compliance/authorizations"
                  className="btn btn-sm btn-outline-primary"
                >
                  Manage Domain Authorizations
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NewScan;
