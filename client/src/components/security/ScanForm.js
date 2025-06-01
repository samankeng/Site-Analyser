// frontend/src/components/security/ScanForm.js - Complete Fixed Version

import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { scanService } from "../../services/scanService";

const ScanForm = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [scanMode, setScanMode] = useState("passive");
  const [scanTypes, setScanTypes] = useState({
    headers: true,
    ssl: true,
    vulnerabilities: true,
    content: false,
    ports: false,
    csp: true,
    cookies: false,
    cors: false,
    server: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanModes, setScanModes] = useState({});
  const [complianceStatus, setComplianceStatus] = useState(null);
  const [urlValidation, setUrlValidation] = useState({
    isValid: true,
    message: "",
  });
  // NEW: Track URL-specific authorization
  const [urlAuthorization, setUrlAuthorization] = useState(null);
  const [checkingAuth, setCheckingAuth] = useState(false);

  // Available scan types with details
  const availableScanTypes = [
    {
      id: "headers",
      name: "HTTP Headers Analysis",
      description: "Examines HTTP headers for missing security headers",
      category: "Web Security",
      icon: "🛡️",
      modes: ["passive", "active", "mixed"],
      priority: "high",
    },
    {
      id: "ssl",
      name: "SSL/TLS Configuration",
      description: "Validates certificate and checks for TLS vulnerabilities",
      category: "Web Security",
      icon: "🔒",
      modes: ["passive", "active", "mixed"],
      priority: "high",
    },
    {
      id: "vulnerabilities",
      name: "Vulnerability Scan",
      description: "Detects common web vulnerabilities and misconfigurations",
      category: "Web Security",
      icon: "⚠️",
      modes: ["passive", "active", "mixed"],
      priority: "high",
    },
    {
      id: "csp",
      name: "Content Security Policy",
      description: "Evaluates CSP headers to prevent XSS attacks",
      category: "Web Security",
      icon: "🛡️",
      modes: ["passive", "active", "mixed"],
      priority: "medium",
    },
    {
      id: "content",
      name: "Content Analysis",
      description: "Analyzes page content for SEO and security issues",
      category: "Content Quality",
      icon: "📄",
      modes: ["passive", "active", "mixed"],
      priority: "medium",
    },
    {
      id: "cookies",
      name: "Cookie Security",
      description:
        "Analyzes cookies for security issues and proper configuration",
      category: "Web Security",
      icon: "🍪",
      modes: ["passive", "active", "mixed"],
      priority: "medium",
    },
    {
      id: "cors",
      name: "CORS Configuration",
      description:
        "Checks Cross-Origin Resource Sharing settings for vulnerabilities",
      category: "Web Security",
      icon: "🔄",
      modes: ["passive", "active", "mixed"],
      priority: "medium",
    },
    {
      id: "ports",
      name: "Port Scanning",
      description: "Checks for open ports and services on the target",
      category: "Infrastructure",
      icon: "🖥️",
      modes: ["active", "mixed"], // Only available in active modes
      priority: "low",
    },
    {
      id: "server",
      name: "Server Analysis",
      description: "Examines server configuration and information disclosure",
      category: "Infrastructure",
      icon: "🖧",
      modes: ["passive", "active", "mixed"],
      priority: "low",
    },
  ];

  // Group scan types by category and sort by priority
  const scanTypesByCategory = availableScanTypes
    .sort((a, b) => {
      const priorityOrder = { high: 0, medium: 1, low: 2 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    })
    .reduce((acc, scanType) => {
      if (!acc[scanType.category]) {
        acc[scanType.category] = [];
      }
      acc[scanType.category].push(scanType);
      return acc;
    }, {});

  useEffect(() => {
    loadScanModes();
    checkComplianceStatus();
  }, []);

  // Listen for compliance changes when page becomes visible again
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        checkComplianceStatus();
      }
    };

    const handleFocus = () => {
      checkComplianceStatus();
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleFocus);

    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("focus", handleFocus);
    };
  }, []);

  // URL validation with debouncing AND authorization check
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      validateUrl(url);
      if (url && urlValidation.isValid) {
        checkUrlAuthorization(url);
      }
    }, 500);

    return () => clearTimeout(timeoutId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  const validateUrl = useCallback((inputUrl) => {
    if (!inputUrl) {
      setUrlValidation({ isValid: true, message: "" });
      setUrlAuthorization(null);
      return;
    }

    try {
      // Add protocol if missing for validation
      let testUrl = inputUrl;
      if (!testUrl.startsWith("http://") && !testUrl.startsWith("https://")) {
        testUrl = "https://" + testUrl;
      }

      const urlObj = new URL(testUrl);

      // Check for common issues
      if (urlObj.hostname === "localhost" || urlObj.hostname === "127.0.0.1") {
        setUrlValidation({
          isValid: true,
          message: "⚠️ Localhost URLs can only be scanned in development mode",
        });
      } else if (urlObj.protocol !== "https:" && urlObj.protocol !== "http:") {
        setUrlValidation({
          isValid: false,
          message: "URL must use HTTP or HTTPS protocol",
        });
      } else {
        setUrlValidation({ isValid: true, message: "✅ Valid URL format" });
      }
    } catch {
      setUrlValidation({
        isValid: false,
        message: "Invalid URL format. Please enter a valid URL.",
      });
    }
  }, []);

  // NEW: Check URL-specific authorization
  const checkUrlAuthorization = async (inputUrl) => {
    if (!inputUrl || !complianceStatus) return;

    try {
      setCheckingAuth(true);

      // Add protocol if missing
      let targetUrl = inputUrl;
      if (
        !targetUrl.startsWith("http://") &&
        !targetUrl.startsWith("https://")
      ) {
        targetUrl = "https://" + targetUrl;
      }

      const response = await scanService.checkUrlAuthorization(targetUrl);
      setUrlAuthorization(response);

      console.log("URL Authorization Check:", response); // DEBUG
    } catch (error) {
      console.error("Error checking URL authorization:", error);
      setUrlAuthorization(null);
    } finally {
      setCheckingAuth(false);
    }
  };

  const loadScanModes = async () => {
    try {
      const modes = await scanService.getScanModes();
      setScanModes(modes);
    } catch (error) {
      console.error("Error loading scan modes:", error);
    }
  };

  const checkComplianceStatus = async () => {
    try {
      const status = await scanService.getComplianceStatus();
      setComplianceStatus(status);
      console.log("Compliance status updated:", status); // DEBUG
    } catch (error) {
      console.error("Error checking compliance:", error);
      setComplianceStatus(null);
    }
  };

  // Expose function globally so it can be called from compliance components
  useEffect(() => {
    window.refreshComplianceStatus = checkComplianceStatus;
    return () => {
      delete window.refreshComplianceStatus;
    };
  }, []);

  const handleCheckboxChange = (e) => {
    const { name, checked } = e.target;
    setScanTypes((prev) => ({ ...prev, [name]: checked }));
  };

  const selectPreset = (presetType) => {
    const updatedScanTypes = { ...scanTypes };

    // Reset all to false first
    Object.keys(updatedScanTypes).forEach((type) => {
      updatedScanTypes[type] = false;
    });

    // Apply preset
    switch (presetType) {
      case "quick":
        // Quick scan - essential security checks only
        ["headers", "ssl", "csp"].forEach((type) => {
          const scanType = availableScanTypes.find((st) => st.id === type);
          if (scanType && scanType.modes.includes(scanMode)) {
            updatedScanTypes[type] = true;
          }
        });
        break;

      case "comprehensive":
        // Comprehensive scan - all available types for current mode
        availableScanTypes.forEach((scanType) => {
          if (scanType.modes.includes(scanMode)) {
            updatedScanTypes[scanType.id] = true;
          }
        });
        break;

      case "security":
        // Security-focused scan
        availableScanTypes
          .filter(
            (type) =>
              type.category === "Web Security" && type.modes.includes(scanMode)
          )
          .forEach((type) => {
            updatedScanTypes[type.id] = true;
          });
        break;

      default:
        break;
    }

    setScanTypes(updatedScanTypes);
  };

  const selectAllScanTypes = () => {
    const compatibleTypes = availableScanTypes.filter((type) =>
      type.modes.includes(scanMode)
    );
    const allSelected = compatibleTypes.every((type) => scanTypes[type.id]);

    const updatedScanTypes = {};
    Object.keys(scanTypes).forEach((type) => {
      const scanType = availableScanTypes.find((st) => st.id === type);
      if (scanType && scanType.modes.includes(scanMode)) {
        updatedScanTypes[type] = !allSelected;
      } else {
        updatedScanTypes[type] = scanTypes[type];
      }
    });

    setScanTypes(updatedScanTypes);
  };

  const selectCategoryTypes = (category) => {
    const categoryTypes = scanTypesByCategory[category]
      .filter((type) => type.modes.includes(scanMode))
      .map((type) => type.id);

    const allCategorySelected = categoryTypes.every((type) => scanTypes[type]);

    const updatedScanTypes = { ...scanTypes };
    categoryTypes.forEach((type) => {
      updatedScanTypes[type] = !allCategorySelected;
    });

    setScanTypes(updatedScanTypes);
  };

  const handleScanModeChange = (newMode) => {
    setScanMode(newMode);

    // Update scan types to only include those compatible with new mode
    const updatedScanTypes = { ...scanTypes };
    Object.keys(updatedScanTypes).forEach((type) => {
      const scanType = availableScanTypes.find((st) => st.id === type);
      if (scanType && !scanType.modes.includes(newMode)) {
        updatedScanTypes[type] = false;
      }
    });
    setScanTypes(updatedScanTypes);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // URL validation
    if (!url) {
      setError("Please enter a URL to scan");
      return;
    }

    if (!urlValidation.isValid) {
      setError("Please enter a valid URL");
      return;
    }

    // Add protocol if missing
    let targetUrl = url;
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }

    // At least one scan type must be selected
    const selectedTypes = Object.keys(scanTypes).filter(
      (type) => scanTypes[type]
    );
    if (selectedTypes.length === 0) {
      setError("Please select at least one scan type");
      return;
    }

    // Check compliance for scan mode using URL-specific authorization
    if (scanMode === "active" && !isScanModeAvailable("active")) {
      setError(
        "Active scanning requires domain authorization for this URL. Please request authorization first."
      );
      return;
    }

    if (scanMode === "mixed" && !isScanModeAvailable("mixed")) {
      setError(
        "Mixed scanning requires domain authorization for this URL. Please request authorization first."
      );
      return;
    }

    setLoading(true);
    setError("");

    try {
      const scanData = {
        target_url: targetUrl,
        scan_types: selectedTypes,
        scan_mode: scanMode,
      };

      const response = await scanService.createScan(scanData);

      if (response.success) {
        navigate(`/scans/${response.data.id}`);
      } else {
        setError(
          response.error?.non_field_errors ||
            "Failed to create scan. Please try again."
        );
      }
    } catch (error) {
      setError("An unexpected error occurred. Please try again.");
      console.error("Scan creation error:", error);
    } finally {
      setLoading(false);
    }
  };

  // Calculate stats
  const compatibleTypes = availableScanTypes.filter((type) =>
    type.modes.includes(scanMode)
  );
  const selectedCount = compatibleTypes.filter(
    (type) => scanTypes[type.id]
  ).length;
  const totalCount = compatibleTypes.length;
  const allSelected = selectedCount === totalCount;

  // UPDATED: Check if scan mode is available using URL-specific authorization
  const isScanModeAvailable = (mode) => {
    if (!complianceStatus) return false;

    const basicAgreementsAccepted =
      complianceStatus.agreements?.terms_of_service &&
      complianceStatus.agreements?.privacy_policy &&
      complianceStatus.agreements?.responsible_disclosure;

    const activeAgreementAccepted =
      complianceStatus.agreements?.active_scanning;

    switch (mode) {
      case "passive":
        // Passive scanning only requires basic agreements
        return basicAgreementsAccepted;
      case "active":
        // Active scanning requires basic + active agreement + URL authorization
        return (
          basicAgreementsAccepted &&
          activeAgreementAccepted &&
          urlAuthorization?.scan_capabilities?.active_enabled === true
        );
      case "mixed":
        // Mixed scanning requires basic + active agreement + URL authorization
        return (
          basicAgreementsAccepted &&
          activeAgreementAccepted &&
          urlAuthorization?.scan_capabilities?.mixed_enabled === true
        );
      default:
        return false;
    }
  };

  // Manual refresh button for compliance status
  const handleRefreshCompliance = () => {
    checkComplianceStatus();
    if (url) {
      checkUrlAuthorization(url);
    }
  };

  // Get domain from URL for authorization display
  const getUrlDomain = (inputUrl) => {
    if (!inputUrl) return null;
    try {
      let testUrl = inputUrl;
      if (!testUrl.startsWith("http://") && !testUrl.startsWith("https://")) {
        testUrl = "https://" + testUrl;
      }
      return new URL(testUrl).hostname;
    } catch {
      return null;
    }
  };

  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h5 className="card-title mb-0">New Security Scan</h5>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={handleRefreshCompliance}
            title="Refresh compliance status"
          >
            <i className="fas fa-sync-alt"></i>
          </button>
        </div>

        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* URL Input with enhanced validation and authorization check */}
          <div className="mb-3">
            <label htmlFor="url" className="form-label">
              Target URL <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className={`form-control ${
                url && !urlValidation.isValid
                  ? "is-invalid"
                  : url && urlValidation.isValid
                  ? "is-valid"
                  : ""
              }`}
              id="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            {urlValidation.message && (
              <div
                className={`form-text ${
                  urlValidation.isValid ? "text-success" : "text-danger"
                }`}
              >
                {urlValidation.message}
              </div>
            )}
            {checkingAuth && (
              <div className="form-text text-info">
                <i className="fas fa-spinner fa-spin me-1"></i>
                Checking domain authorization...
              </div>
            )}
            {urlAuthorization && !checkingAuth && (
              <div className="form-text">
                <strong>Domain: {getUrlDomain(url)}</strong>
                <br />
                Active scanning:{" "}
                {urlAuthorization.scan_capabilities?.active_enabled
                  ? "✅ Authorized"
                  : "❌ Not authorized"}
                <br />
                Mixed scanning:{" "}
                {urlAuthorization.scan_capabilities?.mixed_enabled
                  ? "✅ Authorized"
                  : "❌ Not authorized"}
                {!urlAuthorization.scan_capabilities?.active_enabled && (
                  <div className="mt-1">
                    <a
                      href="/compliance/authorizations"
                      className="btn btn-sm btn-outline-primary"
                    >
                      Request Authorization
                    </a>
                  </div>
                )}
              </div>
            )}
            {!urlValidation.message && !checkingAuth && !urlAuthorization && (
              <div className="form-text">
                Enter the full URL including http:// or https://
              </div>
            )}
          </div>

          {/* Scan Mode Selection */}
          <div className="mb-4">
            <label className="form-label">
              Scan Mode <span className="text-danger">*</span>
            </label>
            <div className="row">
              {Object.entries(scanModes).map(([mode, info]) => (
                <div className="col-md-4 mb-3" key={mode}>
                  <div
                    className={`card h-100 ${
                      scanMode === mode ? "border-primary shadow-sm" : ""
                    } ${!isScanModeAvailable(mode) ? "opacity-75" : ""}`}
                  >
                    <div className="card-body">
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="radio"
                          name="scanMode"
                          id={mode}
                          value={mode}
                          checked={scanMode === mode}
                          onChange={(e) => handleScanModeChange(e.target.value)}
                          disabled={!isScanModeAvailable(mode)}
                        />
                        <label className="form-check-label" htmlFor={mode}>
                          <strong>{info.name}</strong>
                        </label>
                      </div>
                      <small className="text-muted d-block mt-2">
                        {info.description}
                      </small>
                      <div className="mt-2">
                        <span
                          className={`badge ${
                            info.legal_risk === "Very Low"
                              ? "bg-success"
                              : info.legal_risk === "Medium"
                              ? "bg-warning"
                              : "bg-danger"
                          } me-2`}
                        >
                          Risk: {info.legal_risk}
                        </span>
                        {info.authorization_required && (
                          <span className="badge bg-info">Auth Required</span>
                        )}
                      </div>
                      {!isScanModeAvailable(mode) && (
                        <div className="mt-2">
                          <small className="text-danger">
                            <i className="fas fa-exclamation-triangle me-1"></i>
                            {mode === "passive"
                              ? "Basic agreements required"
                              : "Domain authorization required"}
                          </small>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Scan Mode Details */}
          {scanModes[scanMode] && (
            <div className="alert alert-info mb-4">
              <h6 className="alert-heading">
                <i className="fas fa-info-circle me-2"></i>
                Selected Mode: {scanModes[scanMode].name}
              </h6>
              <p className="mb-2">{scanModes[scanMode].description}</p>
              <hr />
              <p className="mb-0">
                <strong>Requirements:</strong>
              </p>
              <ul className="mb-0">
                {scanModes[scanMode].requirements?.map((req, index) => (
                  <li key={index}>{req}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Scan Types Selection */}
          <div className="mb-4">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <label className="form-label mb-0">
                Scan Types <span className="text-danger">*</span>
                <small className="text-muted d-block">
                  ({selectedCount}/{totalCount} selected)
                </small>
              </label>

              {/* Preset buttons */}
              <div className="btn-group" role="group">
                <button
                  type="button"
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => selectPreset("quick")}
                  disabled={totalCount === 0}
                >
                  Quick Scan
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => selectPreset("security")}
                  disabled={totalCount === 0}
                >
                  Security Focus
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-primary"
                  onClick={() => selectPreset("comprehensive")}
                  disabled={totalCount === 0}
                >
                  Comprehensive
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary"
                  onClick={selectAllScanTypes}
                  disabled={totalCount === 0}
                >
                  {allSelected ? "Clear All" : "Select All"}
                </button>
              </div>
            </div>

            {/* Group checkboxes by category */}
            {Object.entries(scanTypesByCategory).map(([category, types]) => {
              const compatibleTypesInCategory = types.filter((type) =>
                type.modes.includes(scanMode)
              );

              if (compatibleTypesInCategory.length === 0) return null;

              const categorySelected = compatibleTypesInCategory.filter(
                (type) => scanTypes[type.id]
              ).length;

              return (
                <div key={category} className="mb-4">
                  <div className="d-flex justify-content-between align-items-center">
                    <h6 className="text-muted mb-2 ms-1">
                      {category}
                      <small className="text-muted ms-2">
                        ({categorySelected}/{compatibleTypesInCategory.length})
                      </small>
                    </h6>
                    <button
                      type="button"
                      className="btn btn-sm btn-link p-0 text-decoration-none text-muted"
                      onClick={() => selectCategoryTypes(category)}
                    >
                      {compatibleTypesInCategory.every(
                        (type) => scanTypes[type.id]
                      )
                        ? "Deselect All"
                        : "Select All"}
                    </button>
                  </div>

                  <div className="row">
                    {compatibleTypesInCategory.map((scanType) => (
                      <div className="col-md-6 mb-3" key={scanType.id}>
                        <div className="card h-100 border-light">
                          <div className="card-body p-3">
                            <div className="form-check">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                id={scanType.id}
                                name={scanType.id}
                                checked={scanTypes[scanType.id] || false}
                                onChange={handleCheckboxChange}
                              />
                              <label
                                className="form-check-label d-flex flex-column"
                                htmlFor={scanType.id}
                              >
                                <span className="fw-medium">
                                  <span className="me-2">{scanType.icon}</span>
                                  {scanType.name}
                                  {scanType.priority === "high" && (
                                    <span className="badge bg-primary ms-2 small">
                                      Recommended
                                    </span>
                                  )}
                                </span>
                                <small className="text-muted mt-1">
                                  {scanType.description}
                                </small>
                                <small className="text-info mt-1">
                                  Mode:{" "}
                                  {scanMode === "passive"
                                    ? "Passive analysis only"
                                    : scanMode === "active"
                                    ? "Active testing"
                                    : "Mixed passive + active"}
                                </small>
                              </label>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}

            {totalCount === 0 && (
              <div className="alert alert-warning">
                <i className="fas fa-exclamation-triangle me-2"></i>
                No scan types are available for the selected scan mode. Please
                choose a different scan mode.
              </div>
            )}
          </div>

          {/* Submit Button */}
          <div className="d-grid">
            <button
              type="submit"
              className="btn btn-primary btn-lg"
              disabled={
                loading ||
                selectedCount === 0 ||
                !isScanModeAvailable(scanMode) ||
                !urlValidation.isValid ||
                !url
              }
            >
              {loading ? (
                <>
                  <span
                    className="spinner-border spinner-border-sm me-2"
                    role="status"
                    aria-hidden="true"
                  ></span>
                  Starting{" "}
                  {scanMode.charAt(0).toUpperCase() + scanMode.slice(1)} Scan...
                </>
              ) : (
                <>
                  <i className="fas fa-play me-2"></i>
                  Start {scanMode.charAt(0).toUpperCase() +
                    scanMode.slice(1)}{" "}
                  Scan
                </>
              )}
            </button>
          </div>

          {!isScanModeAvailable(scanMode) && (
            <div className="mt-3 text-center">
              <div className="alert alert-warning">
                <i className="fas fa-info-circle me-2"></i>
                You need to accept additional legal agreements to use this scan
                mode.
                <br />
                <button
                  type="button"
                  className="btn btn-sm btn-outline-primary mt-2 me-2"
                  onClick={() => window.location.reload()}
                >
                  Refresh Page
                </button>
                <a
                  href="/compliance"
                  className="btn btn-sm btn-outline-secondary mt-2"
                >
                  Go to Compliance Settings
                </a>
              </div>
            </div>
          )}

          {/* Scan Summary */}
          {selectedCount > 0 && (
            <div className="mt-3">
              <div className="alert alert-light">
                <strong>Scan Summary:</strong> {selectedCount} scan type
                {selectedCount !== 1 ? "s" : ""} selected using{" "}
                <span className="badge bg-secondary">{scanMode}</span> mode.
                <br />
                <small className="text-muted">
                  Estimated duration:{" "}
                  {scanMode === "passive"
                    ? "2-5 minutes"
                    : scanMode === "active"
                    ? "5-15 minutes"
                    : "10-20 minutes"}
                </small>
              </div>
            </div>
          )}
        </form>
      </div>
    </div>
  );
};

export default ScanForm;
