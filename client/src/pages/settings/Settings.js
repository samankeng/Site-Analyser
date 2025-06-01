// frontend/src/pages/settings/Settings.js

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import SocialAccountsSettings from "../../components/settings/SocialAccountsSettings";
import { authService } from "../../services/authService";
import { scanService } from "../../services/scanService";
import { clearTokens } from "../../utils/storage";

const Settings = () => {
  const navigate = useNavigate();

  const [profile, setProfile] = useState({
    email: "",
    username: "",
    first_name: "",
    last_name: "",
    company: "",
    job_title: "",
  });

  const [password, setPassword] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });

  const [preferences, setPreferences] = useState({
    email_notifications: true,
    scan_completion_alerts: true,
    vulnerability_alerts: true,
    weekly_reports: false,
    dark_mode: false,
  });

  const [loading, setLoading] = useState(false);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [profileSuccess, setProfileSuccess] = useState("");
  const [passwordSuccess, setPasswordSuccess] = useState("");
  const [preferencesSuccess, setPreferencesSuccess] = useState("");
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const [actionSuccess, setActionSuccess] = useState("");
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmAction, setConfirmAction] = useState(null);
  const [actionTitle, setActionTitle] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const [apiKeys, setApiKeys] = useState([]);

  // Helper function to format error messages
  const formatErrorMessage = (errorObj) => {
    if (typeof errorObj === "string") return errorObj;
    if (errorObj?.detail)
      return typeof errorObj.detail === "string"
        ? errorObj.detail
        : JSON.stringify(errorObj.detail);
    if (errorObj?.message) return errorObj.message;
    return JSON.stringify(errorObj);
  };

  // Fetch current user data on component mount
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoadingProfile(true);
        const response = await authService.getUserProfile();

        if (response.success) {
          setProfile({
            email: response.data.email || "",
            username: response.data.username || "",
            first_name: response.data.first_name || "",
            last_name: response.data.last_name || "",
            company: response.data.company || "",
            job_title: response.data.job_title || "",
          });

          if (response.data.preferences) {
            setPreferences((prevPreferences) => ({
              ...prevPreferences,
              ...response.data.preferences,
            }));
          }

          // Also fetch API keys if available
          fetchApiKeys();
        } else {
          setError(
            formatErrorMessage(response.error) ||
              "Failed to load user data. Please try again."
          );
        }
      } catch (error) {
        console.error("Error fetching user data:", error);
        setError("An unexpected error occurred. Please try again.");
      } finally {
        setLoadingProfile(false);
      }
    };

    fetchUserData();
  }, []);

  const fetchApiKeys = async () => {
    try {
      const response = await authService.getApiKeys();
      if (response.success) {
        setApiKeys(response.data || []);
      }
    } catch (error) {
      console.error("Error fetching API keys:", error);
    }
  };

  const handleProfileChange = (e) => {
    const { name, value } = e.target;
    setProfile({ ...profile, [name]: value });
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPassword({ ...password, [name]: value });
  };

  const handlePreferenceChange = (e) => {
    const { name, checked } = e.target;
    setPreferences({ ...preferences, [name]: checked });
  };

  const handleUpdateProfile = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");
    setFieldErrors({});
    setProfileSuccess("");

    try {
      const response = await authService.updateProfile(profile);

      if (response.success) {
        setProfileSuccess("Profile updated successfully.");
        // Update local storage user data
        const userData = JSON.parse(localStorage.getItem("user") || "{}");
        localStorage.setItem(
          "user",
          JSON.stringify({
            ...userData,
            ...profile,
          })
        );
      } else {
        // Handle validation errors
        if (
          typeof response.error === "object" &&
          !Array.isArray(response.error) &&
          response.error !== null
        ) {
          setFieldErrors(response.error);
        } else {
          setError(
            formatErrorMessage(response.error) ||
              "Failed to update profile. Please try again."
          );
        }
      }
    } catch (error) {
      console.error("Profile update error:", error);
      setError("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePassword = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");
    setFieldErrors({});
    setPasswordSuccess("");

    // Validate password match
    if (password.new_password !== password.confirm_password) {
      setFieldErrors({
        confirm_password: "Passwords do not match.",
      });
      setLoading(false);
      return;
    }

    try {
      const response = await authService.updateProfile({
        current_password: password.current_password,
        new_password: password.new_password,
      });

      if (response.success) {
        setPasswordSuccess("Password updated successfully.");
        setPassword({
          current_password: "",
          new_password: "",
          confirm_password: "",
        });
      } else {
        // Handle validation errors
        if (
          typeof response.error === "object" &&
          !Array.isArray(response.error) &&
          response.error !== null
        ) {
          setFieldErrors(response.error);
        } else {
          setError(
            formatErrorMessage(response.error) ||
              "Failed to update password. Please try again."
          );
        }
      }
    } catch (error) {
      console.error("Password update error:", error);
      setError("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePreferences = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");
    setPreferencesSuccess("");

    try {
      const response = await authService.updateProfile({
        preferences: preferences,
      });

      if (response.success) {
        setPreferencesSuccess("Preferences updated successfully.");
      } else {
        setError(
          formatErrorMessage(response.error) ||
            "Failed to update preferences. Please try again."
        );
      }
    } catch (error) {
      console.error("Preferences update error:", error);
      setError("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Account action methods

  const handleExportData = async () => {
    setLoading(true);
    setError("");
    setActionSuccess("");

    try {
      const response = await authService.exportUserData();

      if (response.success) {
        // Create and download file with exported data
        const dataStr = JSON.stringify(response.data, null, 2);
        const dataBlob = new Blob([dataStr], { type: "application/json" });
        const url = window.URL.createObjectURL(dataBlob);
        const link = document.createElement("a");

        const filename = `${profile.username || "user"}_data_export_${
          new Date().toISOString().split("T")[0]
        }.json`;

        link.href = url;
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        setActionSuccess("Your data has been exported successfully.");
      } else {
        setError(
          formatErrorMessage(response.error) ||
            "Failed to export data. Please try again."
        );
      }
    } catch (error) {
      console.error("Data export error:", error);
      setError("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteScanHistory = async () => {
    showConfirmationModal(
      "Delete Scan History",
      "Are you sure you want to delete all your scan history? This action cannot be undone.",
      async () => {
        setLoading(true);
        setError("");
        setActionSuccess("");

        try {
          // Use scanService instead of authService for scan-related actions
          const response = await scanService.deleteScanHistory();

          if (response.success) {
            setActionSuccess(
              "Your scan history has been deleted successfully."
            );
          } else {
            setError(
              formatErrorMessage(response.error) ||
                "Failed to delete scan history. Please try again."
            );
          }
        } catch (error) {
          console.error("Delete scan history error:", error);
          setError(
            "An unexpected error occurred while deleting scan history. The endpoint may not be available."
          );
        } finally {
          setLoading(false);
        }
      }
    );
  };

  const handleDeactivateAccount = async () => {
    showConfirmationModal(
      "Deactivate Account",
      "Are you sure you want to deactivate your account? All your data will be inaccessible. This action can be reversed by contacting support.",
      async () => {
        setLoading(true);
        setError("");
        setActionSuccess("");

        try {
          const response = await authService.deactivateAccount();

          if (response.success) {
            setActionSuccess(
              "Your account has been deactivated. You will be logged out in 5 seconds."
            );
            // Log out the user after 5 seconds
            setTimeout(() => {
              clearTokens();
              localStorage.removeItem("user");
              navigate("/login");
            }, 5000);
          } else {
            setError(
              formatErrorMessage(response.error) ||
                "Failed to deactivate account. Please try again."
            );
          }
        } catch (error) {
          console.error("Account deactivation error:", error);
          setError("An unexpected error occurred. Please try again.");
        } finally {
          setLoading(false);
        }
      }
    );
  };

  const showConfirmationModal = (title, message, onConfirm) => {
    setActionTitle(title);
    setActionMessage(message);
    setConfirmAction(() => onConfirm);
    setShowConfirmModal(true);
  };

  const handleConfirmAction = () => {
    if (confirmAction) {
      confirmAction();
    }
    setShowConfirmModal(false);
  };

  const handleCancelAction = () => {
    setShowConfirmModal(false);
  };

  // API key management

  const handleGenerateApiKey = async () => {
    setLoading(true);
    setError("");
    setActionSuccess("");

    try {
      const response = await authService.generateApiKey();

      if (response.success) {
        setActionSuccess("New API key generated successfully.");
        // Refresh API keys
        fetchApiKeys();
      } else {
        setError(
          formatErrorMessage(response.error) ||
            "Failed to generate API key. Please try again."
        );
      }
    } catch (error) {
      console.error("API key generation error:", error);
      setError("An unexpected error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyApiKey = (key) => {
    navigator.clipboard
      .writeText(key)
      .then(() => {
        setActionSuccess("API key copied to clipboard.");
        setTimeout(() => setActionSuccess(""), 3000);
      })
      .catch((err) => {
        console.error("Could not copy text: ", err);
        setError("Failed to copy API key.");
      });
  };

  if (loadingProfile) {
    return (
      <div className="container mt-4">
        <div className="d-flex justify-content-center my-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-4 mb-5">
      <h1>User Settings</h1>
      <p className="text-muted mb-4">
        Manage your account and application preferences.
      </p>

      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}

      {actionSuccess && (
        <div className="alert alert-success" role="alert">
          {actionSuccess}
        </div>
      )}

      <div className="row">
        <div className="col-lg-8">
          {/* Profile Section */}
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light">
              <h5 className="mb-0">Profile Information</h5>
            </div>
            <div className="card-body">
              {profileSuccess && (
                <div className="alert alert-success" role="alert">
                  {profileSuccess}
                </div>
              )}

              <form onSubmit={handleUpdateProfile}>
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="email" className="form-label">
                      Email address
                    </label>
                    <input
                      type="email"
                      className={`form-control ${
                        fieldErrors.email ? "is-invalid" : ""
                      }`}
                      id="email"
                      name="email"
                      value={profile.email}
                      onChange={handleProfileChange}
                      required
                    />
                    {fieldErrors.email && (
                      <div className="invalid-feedback">
                        {typeof fieldErrors.email === "string"
                          ? fieldErrors.email
                          : JSON.stringify(fieldErrors.email)}
                      </div>
                    )}
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="username" className="form-label">
                      Username
                    </label>
                    <input
                      type="text"
                      className={`form-control ${
                        fieldErrors.username ? "is-invalid" : ""
                      }`}
                      id="username"
                      name="username"
                      value={profile.username}
                      onChange={handleProfileChange}
                      required
                    />
                    {fieldErrors.username && (
                      <div className="invalid-feedback">
                        {typeof fieldErrors.username === "string"
                          ? fieldErrors.username
                          : JSON.stringify(fieldErrors.username)}
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
                      className="form-control"
                      id="first_name"
                      name="first_name"
                      value={profile.first_name}
                      onChange={handleProfileChange}
                    />
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="last_name" className="form-label">
                      Last Name
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="last_name"
                      name="last_name"
                      value={profile.last_name}
                      onChange={handleProfileChange}
                    />
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label htmlFor="company" className="form-label">
                      Company
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="company"
                      name="company"
                      value={profile.company}
                      onChange={handleProfileChange}
                    />
                  </div>

                  <div className="col-md-6 mb-3">
                    <label htmlFor="job_title" className="form-label">
                      Job Title
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      id="job_title"
                      name="job_title"
                      value={profile.job_title}
                      onChange={handleProfileChange}
                    />
                  </div>
                </div>

                <div className="d-flex justify-content-end mt-3">
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
                        Saving...
                      </>
                    ) : (
                      "Update Profile"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>

          {/* Password Section */}
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light">
              <h5 className="mb-0">Change Password</h5>
            </div>
            <div className="card-body">
              {passwordSuccess && (
                <div className="alert alert-success" role="alert">
                  {passwordSuccess}
                </div>
              )}

              <form onSubmit={handleUpdatePassword}>
                <div className="mb-3">
                  <label htmlFor="current_password" className="form-label">
                    Current Password
                  </label>
                  <input
                    type="password"
                    className={`form-control ${
                      fieldErrors.current_password ? "is-invalid" : ""
                    }`}
                    id="current_password"
                    name="current_password"
                    value={password.current_password}
                    onChange={handlePasswordChange}
                    required
                  />
                  {fieldErrors.current_password && (
                    <div className="invalid-feedback">
                      {typeof fieldErrors.current_password === "string"
                        ? fieldErrors.current_password
                        : JSON.stringify(fieldErrors.current_password)}
                    </div>
                  )}
                </div>

                <div className="mb-3">
                  <label htmlFor="new_password" className="form-label">
                    New Password
                  </label>
                  <input
                    type="password"
                    className={`form-control ${
                      fieldErrors.new_password ? "is-invalid" : ""
                    }`}
                    id="new_password"
                    name="new_password"
                    value={password.new_password}
                    onChange={handlePasswordChange}
                    required
                  />
                  {fieldErrors.new_password && (
                    <div className="invalid-feedback">
                      {typeof fieldErrors.new_password === "string"
                        ? fieldErrors.new_password
                        : JSON.stringify(fieldErrors.new_password)}
                    </div>
                  )}
                  <div className="form-text">
                    Password must be at least 8 characters long with a
                    combination of letters, numbers, and symbols.
                  </div>
                </div>

                <div className="mb-3">
                  <label htmlFor="confirm_password" className="form-label">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    className={`form-control ${
                      fieldErrors.confirm_password ? "is-invalid" : ""
                    }`}
                    id="confirm_password"
                    name="confirm_password"
                    value={password.confirm_password}
                    onChange={handlePasswordChange}
                    required
                  />
                  {fieldErrors.confirm_password && (
                    <div className="invalid-feedback">
                      {typeof fieldErrors.confirm_password === "string"
                        ? fieldErrors.confirm_password
                        : JSON.stringify(fieldErrors.confirm_password)}
                    </div>
                  )}
                </div>

                <div className="d-flex justify-content-end">
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
                        Updating...
                      </>
                    ) : (
                      "Change Password"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>

          {/* Preferences Section */}
          <div className="card shadow-sm">
            <div className="card-header bg-light">
              <h5 className="mb-0">Notification Preferences</h5>
            </div>
            <div className="card-body">
              {preferencesSuccess && (
                <div className="alert alert-success" role="alert">
                  {preferencesSuccess}
                </div>
              )}

              <form onSubmit={handleUpdatePreferences}>
                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="email_notifications"
                    name="email_notifications"
                    checked={preferences.email_notifications}
                    onChange={handlePreferenceChange}
                  />
                  <label
                    className="form-check-label"
                    htmlFor="email_notifications"
                  >
                    Email Notifications
                  </label>
                  <div className="form-text">
                    Receive general email notifications about your account.
                  </div>
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="scan_completion_alerts"
                    name="scan_completion_alerts"
                    checked={preferences.scan_completion_alerts}
                    onChange={handlePreferenceChange}
                  />
                  <label
                    className="form-check-label"
                    htmlFor="scan_completion_alerts"
                  >
                    Scan Completion Alerts
                  </label>
                  <div className="form-text">
                    Get notified when your security scans are completed.
                  </div>
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="vulnerability_alerts"
                    name="vulnerability_alerts"
                    checked={preferences.vulnerability_alerts}
                    onChange={handlePreferenceChange}
                  />
                  <label
                    className="form-check-label"
                    htmlFor="vulnerability_alerts"
                  >
                    Critical Vulnerability Alerts
                  </label>
                  <div className="form-text">
                    Receive immediate alerts for critical or high-severity
                    vulnerabilities.
                  </div>
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="weekly_reports"
                    name="weekly_reports"
                    checked={preferences.weekly_reports}
                    onChange={handlePreferenceChange}
                  />
                  <label className="form-check-label" htmlFor="weekly_reports">
                    Weekly Security Reports
                  </label>
                  <div className="form-text">
                    Receive weekly summary reports of all security findings.
                  </div>
                </div>

                <div className="mb-3 form-check">
                  <input
                    type="checkbox"
                    className="form-check-input"
                    id="dark_mode"
                    name="dark_mode"
                    checked={preferences.dark_mode}
                    onChange={handlePreferenceChange}
                  />
                  <label className="form-check-label" htmlFor="dark_mode">
                    Dark Mode
                  </label>
                  <div className="form-text">
                    Enable dark mode for the application interface.
                  </div>
                </div>

                <div className="d-flex justify-content-end">
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
                        Saving...
                      </>
                    ) : (
                      "Save Preferences"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
          <div>
            <SocialAccountsSettings />
          </div>
        </div>

        <div className="col-lg-4">
          {/* Account Actions Sidebar */}
          <div className="card shadow-sm mb-4">
            <div className="card-header bg-light">
              <h5 className="mb-0">Account Actions</h5>
            </div>
            <div className="card-body">
              <div className="d-grid gap-2">
                <button
                  className="btn btn-outline-primary"
                  type="button"
                  onClick={handleExportData}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span
                        className="spinner-border spinner-border-sm me-2"
                        role="status"
                        aria-hidden="true"
                      ></span>
                      Exporting...
                    </>
                  ) : (
                    "Export My Data"
                  )}
                </button>
                <button
                  className="btn btn-outline-warning"
                  type="button"
                  onClick={handleDeleteScanHistory}
                  disabled={loading}
                >
                  Delete Scan History
                </button>
                <button
                  className="btn btn-outline-danger"
                  type="button"
                  onClick={handleDeactivateAccount}
                  disabled={loading}
                >
                  Deactivate Account
                </button>
                {/* Add the social accounts component */}
              </div>
            </div>
          </div>

          {/* API Keys Section */}
          {/* <div className="card shadow-sm">
            <div className="card-header bg-light">
              <h5 className="mb-0">API Keys</h5>
            </div>
            <div className="card-body">
              <p className="text-muted">Manage your API keys for programmatic access to our services.</p>
              <div className="d-grid">
                <button 
                  className="btn btn-outline-primary" 
                  type="button"
                  onClick={handleGenerateApiKey}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Generating...
                    </>
                  ) : (
                    'Generate New API Key'
                  )}
                </button>
              </div>
              
              <div className="mt-3">
                {apiKeys && apiKeys.length > 0 ? (
                  apiKeys.map((apiKey, index) => (
                    <div key={index} className="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                      <div>
                        <small className="d-block text-muted">{apiKey.name || (index === 0 ? 'Production' : 'Development')}</small>
                        <small>{apiKey.masked_key || '••••••••••••' + (apiKey.key ? apiKey.key.slice(-4) : 'XXXX')}</small>
                      </div>
                      <button 
                        className="btn btn-sm btn-outline-secondary"
                        onClick={() => handleCopyApiKey(apiKey.key)}
                      >
                        Copy
                      </button>
                    </div>
                  ))
                ) : (
                  <div className="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                    <div>
                      <small className="d-block text-muted">Production</small>
                      <small>••••••••••••ABCD</small>
                    </div>
                    <button 
                      className="btn btn-sm btn-outline-secondary"
                      onClick={() => handleCopyApiKey('Production key not available')}
                    >
                      Copy
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div> */}
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div
          className="modal"
          tabIndex="-1"
          style={{ display: "block", backgroundColor: "rgba(0,0,0,0.5)" }}
        >
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">{actionTitle}</h5>
                <button
                  type="button"
                  className="btn-close"
                  onClick={handleCancelAction}
                ></button>
              </div>
              <div className="modal-body">
                <p>{actionMessage}</p>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={handleCancelAction}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={handleConfirmAction}
                >
                  Confirm
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
