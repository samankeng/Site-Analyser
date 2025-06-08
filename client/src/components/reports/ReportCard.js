// frontend/src/components/reports/ReportCard.js - Updated for PDF-only reports

import { Link } from "react-router-dom";
import { reportService } from "../../services/reportService";
import {
  getSeverityBadgeClass,
  getStatusBadgeClass,
} from "../../utils/securityUtils";

const ReportCard = ({ report, isSelected, onSelectReport }) => {
  // Helper function to display the date in a user-friendly format
  const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    const options = {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    };
    return new Date(dateString).toLocaleDateString(undefined, options);
  };

  // Function to get finding counts summary
  const getVulnerabilitySummary = (report) => {
    if (!report.findings_summary || !report.findings_summary.counts) {
      return null;
    }

    const { counts } = report.findings_summary;

    return (
      <div className="d-flex mt-2">
        {counts.critical > 0 && (
          <span className="badge bg-danger me-1">
            {counts.critical} Critical
          </span>
        )}
        {counts.high > 0 && (
          <span className="badge bg-warning text-dark me-1">
            {counts.high} High
          </span>
        )}
        {counts.medium > 0 && (
          <span className="badge bg-info text-dark me-1">
            {counts.medium} Medium
          </span>
        )}
        {counts.low > 0 && (
          <span className="badge bg-secondary me-1">{counts.low} Low</span>
        )}
      </div>
    );
  };

  // Handle PDF download - simplified to use scan ID only
  const handleDownloadPdf = async () => {
    try {
      await reportService.generatePdf(report.id);
    } catch (error) {
      console.error("Error downloading PDF:", error);
      alert("Failed to download PDF. Please try again.");
    }
  };

  // Always link to scan detail page since reports are virtual
  const detailsLink = `/scans/${report.id}`;

  return (
    <div
      className={`card shadow-sm h-100 ${isSelected ? "border-primary" : ""}`}
    >
      <div className="card-body">
        <div className="form-check position-absolute top-0 end-0 m-2">
          <input
            className="form-check-input"
            type="checkbox"
            checked={isSelected}
            onChange={onSelectReport}
            id={`report-${report.id}`}
          />
        </div>

        <h5 className="card-title mb-1">
          {report.name || `Security Report for ${report.target_url}`}
        </h5>

        <p className="text-muted mb-2">
          <small>{report.target_url}</small>
        </p>

        <div className="mb-2">
          <span className={`badge ${getStatusBadgeClass(report.status)}`}>
            {report.status_display || report.status}
          </span>

          {report.highest_severity && report.highest_severity !== "none" && (
            <span
              className={`badge ms-2 ${getSeverityBadgeClass(
                report.highest_severity
              )}`}
            >
              {report.highest_severity_display || report.highest_severity}
            </span>
          )}
        </div>

        {getVulnerabilitySummary(report)}

        <div className="mt-3">
          <small className="text-muted">
            <strong>Created:</strong> {formatDate(report.created_at)}
          </small>
          {report.completed_at && (
            <small className="text-muted d-block">
              <strong>Completed:</strong> {formatDate(report.completed_at)}
            </small>
          )}
        </div>

        <div className="mt-3">
          <small className="text-muted">
            <strong>Scan Types:</strong>{" "}
            {report.scan_types?.join(", ") || "Full Scan"}
          </small>
        </div>

        {/* Security Score Display */}
        {report.security_score !== undefined && (
          <div className="mt-3">
            <small className="text-muted d-block">
              <strong>Security Score:</strong>{" "}
              <span className="fw-bold">{report.security_score}/100</span>
            </small>
          </div>
        )}
      </div>

      <div className="card-footer bg-transparent">
        <Link to={detailsLink} className="btn btn-sm btn-outline-primary">
          View Details
        </Link>

        {report.status === "completed" && (
          <button
            className="btn btn-sm btn-outline-secondary ms-2"
            onClick={handleDownloadPdf}
          >
            Download PDF
          </button>
        )}
      </div>
    </div>
  );
};

export default ReportCard;
