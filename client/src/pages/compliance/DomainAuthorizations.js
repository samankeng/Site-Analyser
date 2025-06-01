import { useEffect, useState } from "react";
import api from "../../services/api";

const DomainAuthorizations = () => {
  const [authorizations, setAuthorizations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRequestForm, setShowRequestForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // State for details modal
  const [selectedAuth, setSelectedAuth] = useState(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);

  // Form state - updated to match DomainAuthorization model
  const [formData, setFormData] = useState({
    domain: "",
    justification: "",
    verification_method: "dns_txt",
    notes: "",
  });
  const [formErrors, setFormErrors] = useState({});

  useEffect(() => {
    fetchAuthorizations();
  }, []);

  // Updated to use compliance domain authorization endpoint
  const fetchAuthorizations = async () => {
    try {
      setLoading(true);
      console.log("Fetching domain authorizations...");

      // Use the compliance endpoint for domain authorizations
      // const response = await api.get("compliance/domains/");
      const response = await api.get("compliance/domain-authorizations/");
      console.log("Authorization response:", response.data);

      let authorizationsData = [];

      // Handle different response structures
      if (Array.isArray(response.data)) {
        authorizationsData = response.data;
      } else if (Array.isArray(response.data?.results)) {
        authorizationsData = response.data.results;
      } else if (response.data && typeof response.data === "object") {
        // If it's an object, check for common array property names
        const possibleArrayKeys = ["authorizations", "data", "items"];
        for (const key of possibleArrayKeys) {
          if (Array.isArray(response.data[key])) {
            authorizationsData = response.data[key];
            break;
          }
        }
      }

      setAuthorizations(authorizationsData);
      console.log("Set authorizations:", authorizationsData);
    } catch (err) {
      console.error("Failed to fetch authorizations:", err);
      setError("Failed to load domain authorizations: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const validateForm = () => {
    const errors = {};

    if (!formData.domain.trim()) {
      errors.domain = "Domain is required";
    } else if (
      !/^[a-zA-Z0-9][a-zA-Z0-9-_.]*[a-zA-Z0-9]$/.test(formData.domain)
    ) {
      errors.domain = "Please enter a valid domain name";
    }

    if (!formData.justification.trim()) {
      errors.justification = "Business justification is required";
    } else if (formData.justification.trim().length < 20) {
      errors.justification =
        "Please provide a more detailed justification (at least 20 characters)";
    }

    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  // Updated to use compliance domain authorization request
  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) return;

    try {
      setSubmitting(true);

      const authorizationData = {
        domain: formData.domain,
        verification_method: formData.verification_method,
        notes: formData.justification,
      };

      console.log("Submitting domain authorization:", authorizationData);

      // Use the compliance endpoint for requesting domain authorization
      const response = await api.post(
        "compliance/request-domain/",
        authorizationData
      );

      console.log("Authorization request response:", response.data);

      // Refresh the authorizations list to show the new request
      await fetchAuthorizations();

      // Reset form
      setFormData({
        domain: "",
        justification: "",
        verification_method: "dns_txt",
        notes: "",
      });
      setShowRequestForm(false);

      // Show success message
      alert(`Domain authorization request submitted for ${formData.domain}`);
    } catch (err) {
      console.error("Failed to submit request:", err);

      // Handle specific errors
      if (err.response?.status === 404) {
        setFormErrors({
          submit:
            "The authorization request endpoint is not yet implemented. Please contact your administrator or check the API documentation.",
        });
      } else if (err.response?.data?.error) {
        setFormErrors({
          submit: err.response.data.error,
        });
      } else if (err.response?.data?.message) {
        setFormErrors({
          submit: err.response.data.message,
        });
      } else {
        setFormErrors({
          submit: err.message || "Failed to submit request. Please try again.",
        });
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));

    // Clear specific field error when user starts typing
    if (formErrors[name]) {
      setFormErrors((prev) => ({ ...prev, [name]: "" }));
    }
  };

  // Updated to use compliance revoke endpoint
  const handleRevokeAuthorization = async (authorizationId) => {
    if (
      window.confirm(
        "Are you sure you want to revoke this authorization? This cannot be undone."
      )
    ) {
      try {
        // Use the compliance endpoint for revoking
        await api.post(
          `compliance/domain-authorizations/${authorizationId}/revoke/`
        );

        await fetchAuthorizations(); // Refresh the list
        alert("Authorization revoked successfully");
      } catch (err) {
        console.error("Failed to revoke authorization:", err);
        alert("Failed to revoke authorization: " + err.message);
      }
    }
  };

  // Handle viewing authorization details
  const handleViewDetails = (auth) => {
    setSelectedAuth(auth);
    setShowDetailsModal(true);
  };

  // Handle canceling authorization request (for pending requests)
  const handleCancelRequest = async (authId) => {
    if (
      window.confirm(
        "Are you sure you want to cancel this authorization request?"
      )
    ) {
      try {
        // Delete the pending authorization
        await api.delete(`compliance/domain-authorizations/${authId}/`);

        await fetchAuthorizations();
        alert("Authorization request cancelled successfully");
      } catch (err) {
        console.error("Failed to cancel request:", err);
        alert("Failed to cancel request: " + err.message);
      }
    }
  };

  // Handle verification attempt
  const handleVerifyDomain = async (authId) => {
    try {
      await api.post("compliance/verify-domain/", {
        domain_id: authId,
      });

      await fetchAuthorizations();
      alert("Domain verification successful!");
    } catch (err) {
      console.error("Failed to verify domain:", err);
      alert("Domain verification failed: " + err.message);
    }
  };

  // Updated status badge to handle DomainAuthorization status
  const getStatusBadgeClass = (auth) => {
    const status = auth.status || "unknown";

    switch (status.toLowerCase()) {
      case "verified":
        return "badge bg-success";
      case "pending":
        return "badge bg-warning text-dark";
      case "rejected":
      case "expired":
        return "badge bg-danger";
      case "revoked":
        return "badge bg-secondary";
      default:
        return "badge bg-light text-dark";
    }
  };

  // Get display status text
  const getDisplayStatus = (auth) => {
    const status = auth.status || "unknown";
    return status.charAt(0).toUpperCase() + status.slice(1);
  };

  // Get display date with fallbacks for DomainAuthorization fields
  const getDisplayDate = (auth, field) => {
    const dateFields = {
      created: ["created_at", "requested_at"],
      expires: ["expires_at", "valid_until"],
      verified: ["verified_at"],
    };

    const fieldsToTry = dateFields[field] || [field];

    for (const dateField of fieldsToTry) {
      if (auth[dateField]) {
        return new Date(auth[dateField]).toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
        });
      }
    }

    return "N/A";
  };

  return (
    <div className="container mt-4">
      <div className="row">
        <div className="col-12">
          <div className="d-flex justify-content-between align-items-center mb-4">
            <div>
              <h3 className="mb-1">Domain Authorizations</h3>
              <p className="text-muted mb-0">
                Manage domain ownership verification for active and mixed
                vulnerability scanning
              </p>
            </div>
            <div className="btn-group">
              <button
                className="btn btn-outline-secondary btn-sm"
                onClick={fetchAuthorizations}
                disabled={loading}
              >
                {loading ? "Refreshing..." : "Refresh"}
              </button>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setShowRequestForm(!showRequestForm)}
              >
                {showRequestForm ? "Cancel Request" : "Request Authorization"}
              </button>
            </div>
          </div>

          {/* Request Form */}
          {showRequestForm && (
            <div className="card mb-4">
              <div className="card-header">
                <h5 className="mb-0">Request Domain Authorization</h5>
                <small className="text-muted">
                  Domain authorization is required for active and mixed scanning
                  modes
                </small>
              </div>
              <div className="card-body">
                <form onSubmit={handleSubmit}>
                  <div className="row">
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label htmlFor="domain" className="form-label">
                          Domain Name <span className="text-danger">*</span>
                        </label>
                        <input
                          type="text"
                          className={`form-control ${
                            formErrors.domain ? "is-invalid" : ""
                          }`}
                          id="domain"
                          name="domain"
                          value={formData.domain}
                          onChange={handleInputChange}
                          placeholder="example.com"
                          disabled={submitting}
                        />
                        {formErrors.domain && (
                          <div className="invalid-feedback">
                            {formErrors.domain}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label
                          htmlFor="verification_method"
                          className="form-label"
                        >
                          Verification Method
                        </label>
                        <select
                          className="form-select"
                          id="verification_method"
                          name="verification_method"
                          value={formData.verification_method}
                          onChange={handleInputChange}
                          disabled={submitting}
                        >
                          <option value="dns_txt">DNS TXT Record</option>
                          <option value="file_upload">
                            File Upload Verification
                          </option>
                          <option value="email_verification">
                            Email Verification
                          </option>
                          <option value="manual_approval">
                            Manual Admin Approval
                          </option>
                        </select>
                      </div>
                    </div>
                  </div>

                  <div className="row">
                    <div className="col-12">
                      <div className="mb-3">
                        <label htmlFor="justification" className="form-label">
                          Business Justification{" "}
                          <span className="text-danger">*</span>
                        </label>
                        <textarea
                          className={`form-control ${
                            formErrors.justification ? "is-invalid" : ""
                          }`}
                          id="justification"
                          name="justification"
                          rows="3"
                          value={formData.justification}
                          onChange={handleInputChange}
                          placeholder="Please explain why you need authorization for this domain and how you'll use it for security testing..."
                          disabled={submitting}
                        />
                        {formErrors.justification && (
                          <div className="invalid-feedback">
                            {formErrors.justification}
                          </div>
                        )}
                        <div className="form-text">
                          Minimum 20 characters. Include details about your
                          authorization and intended use for active scanning.
                        </div>
                      </div>
                    </div>
                  </div>

                  {formErrors.submit && (
                    <div className="alert alert-danger">
                      {formErrors.submit}
                    </div>
                  )}

                  <div className="d-flex gap-2">
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={submitting}
                    >
                      {submitting ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                          ></span>
                          Submitting Request...
                        </>
                      ) : (
                        "Submit Request"
                      )}
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={() => setShowRequestForm(false)}
                      disabled={submitting}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* Authorizations List */}
          {loading ? (
            <div className="d-flex justify-content-center align-items-center py-5">
              <div
                className="spinner-border text-primary me-2"
                role="status"
              ></div>
              <span>Loading domain authorizations...</span>
            </div>
          ) : error ? (
            <div className="alert alert-danger">
              <strong>Error:</strong> {error}
              <button
                className="btn btn-sm btn-outline-danger ms-2"
                onClick={fetchAuthorizations}
              >
                Retry
              </button>
            </div>
          ) : authorizations.length === 0 ? (
            <div className="card">
              <div className="card-body text-center py-5">
                <div className="mb-3">
                  <svg
                    width="48"
                    height="48"
                    fill="currentColor"
                    className="text-muted"
                    viewBox="0 0 16 16"
                  >
                    <path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z" />
                  </svg>
                </div>
                <h5 className="text-muted">No domain authorizations found</h5>
                <p className="text-muted mb-3">
                  Get started by requesting authorization for your first domain
                  to enable active scanning.
                </p>
                <button
                  className="btn btn-primary"
                  onClick={() => setShowRequestForm(true)}
                >
                  Request Authorization
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="row mb-3">
                <div className="col-12">
                  <small className="text-muted">
                    Showing {authorizations.length} authorization
                    {authorizations.length !== 1 ? "s" : ""}
                  </small>
                </div>
              </div>

              <div className="card">
                <div className="table-responsive">
                  <table className="table table-hover mb-0">
                    <thead className="table-light">
                      <tr>
                        <th className="border-0">Domain</th>
                        <th className="border-0">Status</th>
                        <th className="border-0">Requested</th>
                        <th className="border-0">Expires</th>
                        <th className="border-0">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {authorizations.map((auth, index) => (
                        <tr key={auth.id || auth.domain || index}>
                          <td className="align-middle">
                            <strong>{auth.domain}</strong>
                            {auth.verification_method && (
                              <div>
                                <small className="text-muted">
                                  {auth.verification_method
                                    .replace("_", " ")
                                    .toUpperCase()}
                                </small>
                              </div>
                            )}
                          </td>
                          <td className="align-middle">
                            <span className={getStatusBadgeClass(auth)}>
                              {getDisplayStatus(auth)}
                            </span>
                          </td>
                          <td className="align-middle">
                            <small className="text-muted">
                              {getDisplayDate(auth, "created")}
                            </small>
                          </td>
                          <td className="align-middle">
                            <small className="text-muted">
                              {getDisplayDate(auth, "expires")}
                            </small>
                          </td>
                          <td className="align-middle">
                            <div className="btn-group btn-group-sm">
                              <button
                                className="btn btn-outline-primary btn-sm"
                                onClick={() => handleViewDetails(auth)}
                              >
                                <i className="bi bi-eye me-1"></i>
                                Details
                              </button>
                              {auth.status === "pending" && (
                                <>
                                  <button
                                    className="btn btn-outline-success btn-sm"
                                    onClick={() => handleVerifyDomain(auth.id)}
                                  >
                                    <i className="bi bi-check-circle me-1"></i>
                                    Verify
                                  </button>
                                  <button
                                    className="btn btn-outline-warning btn-sm"
                                    onClick={() => handleCancelRequest(auth.id)}
                                  >
                                    <i className="bi bi-x-circle me-1"></i>
                                    Cancel
                                  </button>
                                </>
                              )}
                              {auth.status === "verified" && (
                                <button
                                  className="btn btn-outline-danger btn-sm"
                                  onClick={() =>
                                    handleRevokeAuthorization(auth.id)
                                  }
                                >
                                  <i className="bi bi-ban me-1"></i>
                                  Revoke
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {/* Details Modal */}
          {showDetailsModal && selectedAuth && (
            <div
              className="modal show"
              style={{ display: "block", backgroundColor: "rgba(0,0,0,0.5)" }}
            >
              <div className="modal-dialog modal-lg">
                <div className="modal-content">
                  <div className="modal-header">
                    <h5 className="modal-title">Authorization Details</h5>
                    <button
                      type="button"
                      className="btn-close"
                      onClick={() => setShowDetailsModal(false)}
                    ></button>
                  </div>
                  <div className="modal-body">
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <strong>Domain:</strong> {selectedAuth.domain}
                      </div>
                      <div className="col-md-6">
                        <strong>Status:</strong>
                        <span
                          className={`ms-2 ${getStatusBadgeClass(
                            selectedAuth
                          )}`}
                        >
                          {getDisplayStatus(selectedAuth)}
                        </span>
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <strong>Verification Method:</strong>{" "}
                        {selectedAuth.verification_method
                          ?.replace("_", " ")
                          .toUpperCase() || "N/A"}
                      </div>
                      <div className="col-md-6">
                        <strong>Requested:</strong>{" "}
                        {getDisplayDate(selectedAuth, "created")}
                      </div>
                    </div>
                    <div className="row mb-3">
                      <div className="col-md-6">
                        <strong>Expires:</strong>{" "}
                        {getDisplayDate(selectedAuth, "expires")}
                      </div>
                      <div className="col-md-6">
                        {selectedAuth.verified_at && (
                          <>
                            <strong>Verified:</strong>{" "}
                            {getDisplayDate(selectedAuth, "verified")}
                          </>
                        )}
                      </div>
                    </div>
                    {selectedAuth.verification_token && (
                      <div className="mb-3">
                        <strong>Verification Token:</strong>
                        <div className="mt-1">
                          <code className="small">
                            {selectedAuth.verification_token}
                          </code>
                        </div>
                      </div>
                    )}
                    {selectedAuth.notes && (
                      <div className="mb-3">
                        <strong>Notes:</strong>
                        <div className="mt-2 p-3 bg-light rounded">
                          {selectedAuth.notes}
                        </div>
                      </div>
                    )}
                    {selectedAuth.verification_data && (
                      <div className="mb-3">
                        <strong>Verification Instructions:</strong>
                        <div className="mt-2 p-3 bg-light rounded">
                          <pre className="mb-0 small">
                            {typeof selectedAuth.verification_data === "object"
                              ? JSON.stringify(
                                  selectedAuth.verification_data,
                                  null,
                                  2
                                )
                              : selectedAuth.verification_data}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="modal-footer">
                    {selectedAuth.status === "pending" && (
                      <button
                        type="button"
                        className="btn btn-success"
                        onClick={() => {
                          handleVerifyDomain(selectedAuth.id);
                          setShowDetailsModal(false);
                        }}
                      >
                        Verify Domain
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => setShowDetailsModal(false)}
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DomainAuthorizations;
