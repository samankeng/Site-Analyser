// frontend/src/components/compliance/ComplianceAcceptance.js - Updated for consolidated compliance

import { useEffect, useState } from "react";
import { acceptAgreement, checkComplianceStatus } from "../../services/api";

const ComplianceAcceptance = ({
  onComplianceComplete,
  missingAgreements = [],
}) => {
  const [acceptedAgreements, setAcceptedAgreements] = useState({
    terms_of_service: false,
    privacy_policy: false,
    responsible_disclosure: false,
    active_scanning: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  // Agreement details
  const agreements = {
    terms_of_service: {
      title: "Terms of Service",
      description:
        "By accepting, you agree to use our security scanning service responsibly and in accordance with our terms of service.",
      required: true,
      icon: "📜",
    },
    privacy_policy: {
      title: "Privacy Policy",
      description:
        "We respect your privacy and will handle your data according to our privacy policy and applicable data protection laws.",
      required: true,
      icon: "🔒",
    },
    responsible_disclosure: {
      title: "Responsible Disclosure Guidelines",
      description:
        "You agree to follow responsible disclosure practices for any vulnerabilities found during scanning.",
      required: true,
      icon: "🛡️",
    },
    active_scanning: {
      title: "Active Scanning Agreement",
      description:
        "Additional agreement required for active and mixed scanning modes. This allows more intrusive testing that may trigger security alerts.",
      required: false,
      icon: "⚡",
    },
  };

  useEffect(() => {
    // Check current compliance status
    loadComplianceStatus();
  }, []);

  const loadComplianceStatus = async () => {
    try {
      const status = await checkComplianceStatus();
      if (status && status.agreements) {
        setAcceptedAgreements({
          terms_of_service: status.agreements.terms_of_service || false,
          privacy_policy: status.agreements.privacy_policy || false,
          responsible_disclosure:
            status.agreements.responsible_disclosure || false,
          active_scanning: status.agreements.active_scanning || false,
        });
      }
    } catch (err) {
      console.error("Error loading compliance status:", err);
    }
  };

  const handleAcceptAgreement = async (agreementType) => {
    setLoading(true);
    setError("");
    setSuccessMessage("");

    try {
      // Call API to accept agreement - using the consolidated endpoint
      const response = await acceptAgreement(agreementType);

      if (response.error) {
        throw new Error(response.error);
      }

      // Update local state
      setAcceptedAgreements((prev) => ({
        ...prev,
        [agreementType]: true,
      }));

      setSuccessMessage(
        `${agreements[agreementType].title} accepted successfully!`
      );

      // Check if all required agreements are now accepted
      const updatedAgreements = {
        ...acceptedAgreements,
        [agreementType]: true,
      };

      const allRequiredAccepted =
        updatedAgreements.terms_of_service &&
        updatedAgreements.privacy_policy &&
        updatedAgreements.responsible_disclosure;

      if (allRequiredAccepted) {
        // Give the backend a moment to update, then notify parent
        setTimeout(async () => {
          // Refresh compliance status to ensure it's updated
          await loadComplianceStatus();

          // Also refresh the global compliance status if the function exists
          if (window.refreshComplianceStatus) {
            await window.refreshComplianceStatus();
          }

          // Notify parent component
          if (onComplianceComplete) {
            onComplianceComplete();
          }
        }, 500);
      }
    } catch (err) {
      console.error("Error accepting agreement:", err);
      setError(`Failed to accept agreement: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAcceptAll = async () => {
    setLoading(true);
    setError("");
    setSuccessMessage("");

    try {
      // Accept all required agreements in sequence
      const agreementTypes = [
        "terms_of_service",
        "privacy_policy",
        "responsible_disclosure",
      ];

      for (const agreementType of agreementTypes) {
        if (!acceptedAgreements[agreementType]) {
          await acceptAgreement(agreementType);
          setAcceptedAgreements((prev) => ({
            ...prev,
            [agreementType]: true,
          }));
        }
      }

      setSuccessMessage("All required agreements accepted successfully!");

      // Give the backend a moment to update
      setTimeout(async () => {
        // Refresh compliance status
        await loadComplianceStatus();

        // Also refresh the global compliance status if available
        if (window.refreshComplianceStatus) {
          await window.refreshComplianceStatus();
        }

        // Notify parent component
        if (onComplianceComplete) {
          onComplianceComplete();
        }
      }, 500);
    } catch (err) {
      console.error("Error accepting agreements:", err);
      setError(`Failed to accept agreements: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const allRequiredAccepted =
    acceptedAgreements.terms_of_service &&
    acceptedAgreements.privacy_policy &&
    acceptedAgreements.responsible_disclosure;

  const anyRequiredMissing =
    !acceptedAgreements.terms_of_service ||
    !acceptedAgreements.privacy_policy ||
    !acceptedAgreements.responsible_disclosure;

  return (
    <div className="compliance-acceptance">
      <div className="card shadow-sm">
        <div className="card-body">
          <h5 className="card-title mb-4">
            <i className="fas fa-shield-alt text-primary me-2"></i>
            Legal Compliance Required
          </h5>

          <p className="text-muted mb-4">
            Before you can scan websites, you must accept our legal agreements
            to ensure responsible use of our security scanning service.
          </p>

          {error && (
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
            </div>
          )}

          {successMessage && (
            <div className="alert alert-success" role="alert">
              <i className="fas fa-check-circle me-2"></i>
              {successMessage}
            </div>
          )}

          <div className="agreements-list">
            {Object.entries(agreements).map(([key, agreement]) => {
              const isAccepted = acceptedAgreements[key];
              const isRequired = agreement.required;
              const shouldShow = isRequired || key === "active_scanning";

              if (!shouldShow) return null;

              return (
                <div
                  key={key}
                  className={`agreement-item mb-3 p-3 border rounded ${
                    isAccepted ? "border-success bg-light" : ""
                  }`}
                >
                  <div className="d-flex justify-content-between align-items-start">
                    <div className="flex-grow-1">
                      <h6 className="mb-1">
                        <span className="me-2">{agreement.icon}</span>
                        {agreement.title}
                        {isRequired && (
                          <span className="badge bg-warning text-dark ms-2">
                            Required
                          </span>
                        )}
                        {!isRequired && (
                          <span className="badge bg-info ms-2">Optional</span>
                        )}
                      </h6>
                      <p className="text-muted small mb-0">
                        {agreement.description}
                      </p>
                    </div>
                    <div className="ms-3">
                      {isAccepted ? (
                        <button className="btn btn-success btn-sm" disabled>
                          <i className="fas fa-check me-1"></i>
                          Accepted
                        </button>
                      ) : (
                        <button
                          className="btn btn-primary btn-sm"
                          onClick={() => handleAcceptAgreement(key)}
                          disabled={loading}
                        >
                          Accept
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {anyRequiredMissing && (
            <div className="mt-4 pt-3 border-top">
              <div className="alert alert-warning mb-3">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Agreements Required</strong>
                <br />
                Please accept the required agreements above to enable security
                scanning.
              </div>

              <button
                className="btn btn-primary btn-lg w-100"
                onClick={handleAcceptAll}
                disabled={loading || allRequiredAccepted}
              >
                {loading ? (
                  <>
                    <span
                      className="spinner-border spinner-border-sm me-2"
                      role="status"
                      aria-hidden="true"
                    ></span>
                    Accepting Agreements...
                  </>
                ) : (
                  <>
                    <i className="fas fa-check-double me-2"></i>
                    Accept All Required Agreements
                  </>
                )}
              </button>
            </div>
          )}

          {allRequiredAccepted && (
            <div className="mt-4 pt-3 border-top">
              <div className="alert alert-success">
                <i className="fas fa-check-circle me-2"></i>
                <strong>All required agreements accepted!</strong>
                <br />
                You can now perform passive security scans. Active scanning
                requires domain authorization.
              </div>

              {!acceptedAgreements.active_scanning && (
                <div className="alert alert-info mt-3">
                  <i className="fas fa-info-circle me-2"></i>
                  <strong>Enable Active Scanning:</strong> Accept the optional
                  Active Scanning Agreement above to unlock advanced
                  vulnerability testing capabilities.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Additional Information */}
      <div className="row mt-4">
        <div className="col-md-6">
          <div className="card h-100">
            <div className="card-body">
              <h6 className="card-title">
                <i className="fas fa-search text-primary me-2"></i>
                Passive Scanning
              </h6>
              <p className="card-text small">
                Available after accepting required agreements. Safe,
                non-intrusive analysis of any website.
              </p>
              <ul className="small mb-0">
                <li>HTTP header analysis</li>
                <li>SSL/TLS configuration checks</li>
                <li>Content security analysis</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card h-100">
            <div className="card-body">
              <h6 className="card-title">
                <i className="fas fa-bolt text-warning me-2"></i>
                Active Scanning
              </h6>
              <p className="card-text small">
                Requires Active Scanning Agreement + domain authorization. More
                intrusive testing.
              </p>
              <ul className="small mb-0">
                <li>Vulnerability testing</li>
                <li>Security misconfiguration detection</li>
                <li>Advanced penetration testing</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ComplianceAcceptance;
