// src/components/dashboard/AnomalyDetectionDashboard.js - FIXED VERSION
import { useEffect, useState } from "react";
import anomalyService from "../../services/anomalyService";

const AnomalyDetectionDashboard = ({ scanId }) => {
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [anomalyStats, setAnomalyStats] = useState(null);
  const [retryCount, setRetryCount] = useState(0);
  const [debugInfo, setDebugInfo] = useState(null);

  useEffect(() => {
    const fetchAnomalies = async () => {
      if (!scanId) {
        setLoading(false);
        setDebugInfo({ message: "No scan ID provided" });
        return;
      }

      try {
        setLoading(true);
        setError("");

        console.log(`Fetching anomalies for scan ID: ${scanId}`);

        // Fetch anomalies with enhanced detection
        const response = await anomalyService.getAnomaliesForScan(scanId);

        console.log("Anomaly service response:", response);

        if (response.success) {
          // FIXED: Transform backend anomaly data to frontend format
          const anomaliesData = transformAnomalyData(response.data);
          setAnomalies(anomaliesData);

          // Calculate and set stats
          if (anomaliesData.length > 0) {
            const stats = calculateAnomalyStats(anomaliesData);
            setAnomalyStats(stats);
          }

          setDebugInfo({
            scanId,
            anomaliesFound: anomaliesData.length,
            anomaliesData: anomaliesData,
            timestamp: new Date().toISOString(),
          });

          console.log(`Successfully loaded ${anomaliesData.length} anomalies`);
        } else {
          console.error("Failed to fetch anomalies:", response.error);
          setError(response.error || "Failed to fetch anomalies");
          setAnomalies([]);
        }
      } catch (error) {
        console.error("Error fetching anomalies:", error);
        setError("An unexpected error occurred while fetching anomalies");
        setAnomalies([]);

        // Retry logic for network issues
        if (retryCount < 2) {
          console.log(`Retrying... attempt ${retryCount + 1}`);
          setRetryCount((prev) => prev + 1);
          setTimeout(() => {
            fetchAnomalies();
          }, 2000);
          return;
        }
      } finally {
        setLoading(false);
      }
    };

    fetchAnomalies();
  }, [scanId]);

  // Reset retry count when scanId changes
  useEffect(() => {
    setRetryCount(0);
  }, [scanId]);

  // FIXED: Transform backend anomaly data to match frontend expectations
  const transformAnomalyData = (backendData) => {
    if (!backendData) return [];

    // Handle different response formats
    let anomaliesArray = [];

    if (Array.isArray(backendData)) {
      anomaliesArray = backendData;
    } else if (backendData.anomalies && Array.isArray(backendData.anomalies)) {
      anomaliesArray = backendData.anomalies;
    } else if (backendData.results && Array.isArray(backendData.results)) {
      anomaliesArray = backendData.results;
    }

    // Transform each anomaly to frontend format
    return anomaliesArray.map((anomaly, index) => ({
      id: anomaly.id || `anomaly-${index}`,
      component: getComponentDisplayName(anomaly.type || "Unknown"),
      severity: anomaly.severity || "medium",
      description: anomaly.description || "No description available",
      recommendation: anomaly.recommendation || null,
      score: anomaly.anomaly_score || backendData.anomaly_score || 0,
      details: anomaly.details || {},
      created_at: anomaly.created_at || new Date().toISOString(),
      is_false_positive: false,
      type: anomaly.type || "unknown",
    }));
  };

  // FIXED: Map anomaly types to user-friendly component names
  const getComponentDisplayName = (type) => {
    const componentMap = {
      missing_security_headers: "Security Headers",
      critical_security_headers_missing: "Critical Security Headers",
      ssl_configuration_issues: "SSL/TLS Configuration",
      medium_severity_concentration: "Issue Concentration Analysis",
      high_severity_concentration: "High Severity Issues",
      excessive_issue_count: "Issue Volume Analysis",
      vulnerability_cluster: "Vulnerability Clustering",
      critical_vulnerability_cluster: "Critical Vulnerabilities",
      performance_degradation: "Performance Analysis",
      connection_timeouts: "Connection Issues",
      ssl_test_site_patterns: "SSL Test Site Detection",
      content_security_issues: "Content Security",
      scan_failure_anomalies: "Scan Quality",
      unknown: "General Analysis",
    };

    return componentMap[type] || componentMap["unknown"];
  };

  const calculateAnomalyStats = (anomaliesData) => {
    const stats = {
      total: anomaliesData.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      byComponent: {},
      overallScore: 0,
    };

    anomaliesData.forEach((anomaly) => {
      const severity = anomaly.severity?.toLowerCase() || "low";
      if (stats.bySeverity[severity] !== undefined) {
        stats.bySeverity[severity]++;
      }

      const component = anomaly.component || "Unknown";
      stats.byComponent[component] = (stats.byComponent[component] || 0) + 1;
    });

    // FIXED: Calculate overall score properly
    if (anomaliesData.length > 0) {
      const avgScore =
        anomaliesData.reduce((sum, anomaly) => sum + (anomaly.score || 0), 0) /
        anomaliesData.length;
      stats.overallScore = Math.round(avgScore * 100);
    }

    return stats;
  };

  const handleMarkFalsePositive = async (anomalyId) => {
    try {
      const response = await anomalyService.markAsFalsePositive(anomalyId);
      if (response.success) {
        // Update the anomaly in the local state
        setAnomalies((prev) =>
          prev.map((anomaly) =>
            anomaly.id === anomalyId
              ? { ...anomaly, is_false_positive: true }
              : anomaly
          )
        );
      } else {
        console.error("Failed to mark as false positive:", response.error);
      }
    } catch (error) {
      console.error("Error marking as false positive:", error);
    }
  };

  const handleRetry = () => {
    setRetryCount(0);
    setError("");
    // Trigger re-fetch by updating a dummy state
    setLoading(true);
  };

  if (!scanId) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5 className="d-flex align-items-center">
          <i className="fas fa-exclamation-triangle text-warning me-2"></i>
          Anomaly Detection For Latest Scan
        </h5>
        <p className="text-muted">Select a scan to view anomaly analysis.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5 className="d-flex align-items-center">
          <i className="fas fa-brain text-primary me-2"></i>
          Anomaly Detection For Latest Scan
        </h5>
        <div className="d-flex align-items-center justify-content-center my-4">
          <div className="spinner-border text-primary me-3" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <span className="text-muted">
            {retryCount > 0
              ? `Retrying... (${retryCount}/2)`
              : "Analyzing scan data for anomalies..."}
          </span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5 className="d-flex align-items-center">
          <i className="fas fa-brain text-primary me-2"></i>
          Anomaly Detection For Latest Scan
        </h5>
        <div
          className="alert alert-danger d-flex align-items-center"
          role="alert"
        >
          <i className="fas fa-exclamation-circle me-2"></i>
          <div className="flex-grow-1">
            <strong>Error:</strong> {error}
          </div>
          <button
            className="btn btn-sm btn-outline-danger ms-2"
            onClick={handleRetry}
            title="Retry anomaly detection"
          >
            <i className="fas fa-redo"></i>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="anomaly-dashboard p-3">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h5 className="d-flex align-items-center mb-0">
          <i className="fas fa-brain text-primary me-2"></i>
          Anomaly Detection For Latest Scan
          {anomalies.length > 0 && (
            <span className="badge bg-warning text-dark ms-2">
              {anomalies.length} detected
            </span>
          )}
        </h5>
        {anomalyStats && (
          <div className="text-end">
            <small className="text-muted">Risk Score:</small>
            <span
              className={`badge ms-1 ${getRiskScoreBadgeClass(
                anomalyStats.overallScore
              )}`}
            >
              {anomalyStats.overallScore}/100
            </span>
          </div>
        )}
      </div>

      {/* Anomaly Statistics */}
      {anomalyStats && anomalies.length > 0 && (
        <div className="row mb-3">
          <div className="col-12">
            <div className="card border-0 bg-light">
              <div className="card-body py-2">
                <div className="row text-center">
                  <div className="col">
                    <small className="text-muted d-block">Critical</small>
                    <span className="badge bg-danger">
                      {anomalyStats.bySeverity.critical}
                    </span>
                  </div>
                  <div className="col">
                    <small className="text-muted d-block">High</small>
                    <span className="badge bg-warning">
                      {anomalyStats.bySeverity.high}
                    </span>
                  </div>
                  <div className="col">
                    <small className="text-muted d-block">Medium</small>
                    <span className="badge bg-info">
                      {anomalyStats.bySeverity.medium}
                    </span>
                  </div>
                  <div className="col">
                    <small className="text-muted d-block">Low</small>
                    <span className="badge bg-secondary">
                      {anomalyStats.bySeverity.low}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Anomaly List */}
      {anomalies.length === 0 ? (
        <div className="text-center py-4">
          <i className="fas fa-shield-alt text-success fa-3x mb-3"></i>
          <p className="text-muted mb-2">
            No anomalies detected for this scan.
          </p>
          <small className="text-muted">
            The AI analysis found no unusual patterns or security anomalies.
          </small>
        </div>
      ) : (
        <div className="anomaly-list">
          {anomalies.map((anomaly, index) => (
            <AnomalyCard
              key={anomaly.id || `anomaly-${index}`}
              anomaly={anomaly}
              onMarkFalsePositive={handleMarkFalsePositive}
            />
          ))}
        </div>
      )}

      {/* Debug Info (only in development) */}
      {process.env.NODE_ENV === "development" && debugInfo && (
        <details className="mt-3">
          <summary className="text-muted small">Debug Information</summary>
          <pre className="small text-muted mt-2">
            {JSON.stringify(debugInfo, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
};

// ENHANCED: Separate component for individual anomaly cards
const AnomalyCard = ({ anomaly, onMarkFalsePositive }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div
      className={`anomaly-item card mb-3 border-${getSeverityClass(
        anomaly.severity
      )} ${anomaly.is_false_positive ? "opacity-50" : ""}`}
    >
      <div
        className={`card-header bg-transparent border-${getSeverityClass(
          anomaly.severity
        )} d-flex justify-content-between align-items-start`}
      >
        <div className="flex-grow-1">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="mb-0 d-flex align-items-center">
              <i
                className={`fas ${getSeverityIcon(anomaly.severity)} me-2`}
              ></i>
              {anomaly.component}
            </h6>
            <div className="d-flex align-items-center">
              <span
                className={`badge bg-${getSeverityClass(
                  anomaly.severity
                )} me-2`}
              >
                {anomaly.severity}
              </span>
              {anomaly.is_false_positive && (
                <span className="badge bg-secondary">False Positive</span>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="card-body">
        <p className="card-text mb-2">{anomaly.description}</p>

        {anomaly.recommendation && (
          <div className="alert alert-light border-0 py-2 mb-2">
            <strong className="text-primary">
              <i className="fas fa-lightbulb me-1"></i>
              Recommendation:
            </strong>
            <div className="mt-1">{anomaly.recommendation}</div>
          </div>
        )}

        {/* ENHANCED: Show anomaly type for debugging */}
        {anomaly.type && (
          <div className="mb-2">
            <small className="text-muted">
              <i className="fas fa-tag me-1"></i>
              Type: <code>{anomaly.type}</code>
            </small>
          </div>
        )}

        {/* Additional Details */}
        {anomaly.details && Object.keys(anomaly.details).length > 0 && (
          <div className="mt-2">
            <button
              className="btn btn-sm btn-outline-secondary"
              onClick={() => setIsExpanded(!isExpanded)}
            >
              <i
                className={`fas fa-chevron-${isExpanded ? "up" : "down"} me-1`}
              ></i>
              {isExpanded ? "Hide" : "Show"} Details
            </button>

            {isExpanded && (
              <div className="mt-2 p-2 bg-light rounded">
                <small>
                  {Object.entries(anomaly.details).map(([key, value]) => (
                    <div key={key} className="mb-1">
                      <strong>{key.replace(/_/g, " ").toUpperCase()}:</strong>{" "}
                      {typeof value === "object"
                        ? JSON.stringify(value, null, 2)
                        : String(value)}
                    </div>
                  ))}
                </small>
              </div>
            )}
          </div>
        )}

        <div className="mt-3 d-flex justify-content-between align-items-center">
          <div className="d-flex align-items-center">
            <small className="text-muted me-3">
              <i className="fas fa-chart-line me-1"></i>
              Anomaly Score:{" "}
              <strong>{((anomaly.score || 0) * 100).toFixed(1)}%</strong>
            </small>
            {anomaly.created_at && (
              <small className="text-muted">
                <i className="fas fa-clock me-1"></i>
                {new Date(anomaly.created_at).toLocaleString()}
              </small>
            )}
          </div>

          {!anomaly.is_false_positive && anomaly.id && (
            <button
              className="btn btn-sm btn-outline-secondary"
              onClick={() => onMarkFalsePositive(anomaly.id)}
              title="Mark as false positive"
            >
              <i className="fas fa-flag me-1"></i>
              False Positive
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

// Helper function to get Bootstrap color class based on severity
const getSeverityClass = (severity) => {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "info";
    case "low":
      return "secondary";
    default:
      return "light";
  }
};

// Helper function to get icon based on severity
const getSeverityIcon = (severity) => {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "fa-exclamation-circle";
    case "high":
      return "fa-exclamation-triangle";
    case "medium":
      return "fa-info-circle";
    case "low":
      return "fa-minus-circle";
    default:
      return "fa-question-circle";
  }
};

// Helper function to get risk score badge class
const getRiskScoreBadgeClass = (score) => {
  if (score >= 80) return "bg-danger";
  if (score >= 60) return "bg-warning";
  if (score >= 40) return "bg-info";
  if (score >= 20) return "bg-secondary";
  return "bg-success";
};

export default AnomalyDetectionDashboard;
