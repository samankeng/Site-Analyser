// frontend/src/pages/scans/ScanStatus.js

import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import VulnerabilityList from "../../components/reports/VulnerabilityList";
import ScanProgress from "../../components/security/ScanProgress";
import { reportService } from "../../services/reportService";
import { scanReportService } from "../../services/scanReportService";
import { scanService } from "../../services/scanService";

import {
  getScoreColorClass,
  getSecurityRating,
  getSeverityBadgeClass,
  getStatusBadgeClass,
} from "../../utils/securityUtils";

const ScanStatus = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reportData, setReportData] = useState(null);

  const fetchScan = useCallback(async () => {
    if (!id || id === "undefined") {
      console.error("Invalid scan ID:", id);
      navigate("/dashboard");
      return;
    }

    try {
      setLoading(true);

      const response = await scanService.getScanWithResults(id);

      if (response.success) {
        setScanData(response.data);
        console.log("Scan Results:", response.data.results);

        const virtualReport = reportService.convertScanToReport(response.data); // ✅ define first
        setReportData(virtualReport); // ✅ now set it safely

        // Try loading the real report (matches the PDF)
        if (response.data.status === "completed") {
          try {
            const reportResponse = await scanReportService.getReportForScan(id);
            if (reportResponse.success && reportResponse.data) {
              setReportData(reportResponse.data); // ✅ replace virtual with real if exists
            } else {
              console.warn("No finalized report exists for scan", id);
            }
          } catch (e) {
            console.error("Error getting report for scan:", e);
          }
        }
      } else {
        setError("Failed to fetch scan data");
      }
    } catch (error) {
      console.error("Error fetching scan:", error);
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  }, [id, navigate]);

  // Fetch scan data on component mount
  useEffect(() => {
    fetchScan();
    if (scanData) {
      console.log("Scan Data Structure:", scanData);
    }
  }, [fetchScan]);

  // Poll for updates if scan is in progress
  useEffect(() => {
    if (!scanData || scanData.status !== "in_progress") return;

    const interval = setInterval(() => {
      fetchScan();
    }, 5000); // Poll every 5 seconds

    return () => clearInterval(interval);
  }, [scanData, fetchScan]);

  // Handle scan cancellation
  const handleCancelScan = async () => {
    // Validate id before making API call
    if (!id || id === "undefined") {
      setError("Invalid scan ID");
      return;
    }

    try {
      const response = await scanService.cancelScan(id);
      if (response.success) {
        fetchScan(); // Refresh scan data
      } else {
        setError("Failed to cancel scan");
      }
    } catch (error) {
      console.error("Error cancelling scan:", error);
      setError("An unexpected error occurred");
    }
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center my-5">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container py-4">
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      </div>
    );
  }

  if (!scanData) {
    return (
      <div className="container py-4">
        <div className="alert alert-warning" role="alert">
          Scan not found
        </div>
      </div>
    );
  }

  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Scan Details</h2>
        <div>
          <Link to="/dashboard" className="btn btn-outline-secondary me-2">
            Back to Dashboard
          </Link>
          {scanData.status === "in_progress" && (
            <button className="btn btn-danger" onClick={handleCancelScan}>
              Cancel Scan
            </button>
          )}
        </div>
      </div>

      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <h5 className="card-title">Target: {scanData.target_url}</h5>
          <div className="row mt-3">
            <div className="col-md-6">
              <p>
                <strong>Status:</strong>
                <span
                  className={`badge ${getStatusBadgeClass(
                    scanData.status
                  )} ms-2`}
                >
                  {scanData.status}
                </span>
              </p>
              <p>
                <strong>Scan Types:</strong> {scanData.scan_types.join(", ")}
              </p>
              <p>
                <strong>Created:</strong>{" "}
                {new Date(scanData.created_at).toLocaleString()}
              </p>
            </div>
            <div className="col-md-6">
              {scanData.started_at && (
                <p>
                  <strong>Started:</strong>{" "}
                  {new Date(scanData.started_at).toLocaleString()}
                </p>
              )}
              {scanData.completed_at && (
                <p>
                  <strong>Completed:</strong>{" "}
                  {new Date(scanData.completed_at).toLocaleString()}
                </p>
              )}
              {scanData.error_message && (
                <div className="alert alert-danger">
                  <strong>Error:</strong> {scanData.error_message}
                </div>
              )}
            </div>
          </div>

          {scanData.status === "in_progress" && (
            <ScanProgress scanTypes={scanData.scan_types} />
          )}
        </div>
      </div>

      {/* Results section - shown when scan is completed */}
      {scanData.status === "completed" && (
        <div className="card shadow-sm">
          <div className="card-body">
            <div className="row mb-4">
              <div className="col-md-8">
                <h5 className="card-title">Scan Results</h5>
              </div>
              <div className="col-md-4 text-end">
                <div className="d-inline-block text-center p-3 border rounded">
                  <h6>Security Score</h6>
                  <div
                    className={`display-4 ${getScoreColorClass(
                      scanData.securityScore
                    )}`}
                  >
                    {scanData.securityScore}
                  </div>
                  <div className="text-muted">
                    {getSecurityRating(scanData.securityScore)}
                  </div>
                </div>
              </div>
            </div>

            {/* Severity summary */}
            {/* {Object.keys(scanData.severityCounts).length > 0 && (
              <div className="mb-4">
                <h6>Summary of Findings</h6>
                <div className="d-flex flex-wrap">
                  {Object.entries(scanData.severityCounts).map(([severity, count]) => (
                    <div key={severity} className="me-3 mb-2">
                      <span className={`badge ${getSeverityBadgeClass(severity)} me-1`}>
                        {count}
                      </span>
                      <span className="text-capitalize">{severity}</span>
                    </div>
                  ))}
                </div>
              </div>
            )} */}

            {(() => {
              const counts = reportData?.findings_summary?.counts;
              return counts ? (
                <div className="mb-4">
                  <h6>Summary of Findings</h6>
                  <div className="d-flex flex-wrap">
                    {Object.entries(counts).map(([severity, count]) => (
                      <div key={severity} className="me-3 mb-2">
                        <span
                          className={`badge ${getSeverityBadgeClass(
                            severity
                          )} me-1`}
                        >
                          {count}
                        </span>
                        <span className="text-capitalize">{severity}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null;
            })()}

            {scanData.results.length === 0 ? (
              <div className="alert alert-info">
                No issues found. Your site passed all security checks!
              </div>
            ) : (
              <VulnerabilityList results={scanData.results} />
            )}

            <div className="mt-4">
              <Link to={`/reports/${id}`} className="btn btn-primary">
                View Full Report
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanStatus;
