// frontend/src/components/reports/ReportList.js - Updated for PDF-only reports

import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { reportService } from "../../services/reportService";
import ReportCard from "./ReportCard";

const ReportList = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedReports, setSelectedReports] = useState([]);
  const [filterStatus, setFilterStatus] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortOrder, setSortOrder] = useState("newest");

  // Define fetchReports using useCallback before using it in useEffect
  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      // Use the simplified report service to fetch reports (virtual only)
      const response = await reportService.getReports();

      if (response.success) {
        setReports(Array.isArray(response.data) ? response.data : []);
      } else {
        setError(response.error || "Failed to fetch reports");
        setReports([]);
      }
    } catch (error) {
      console.error("Error fetching reports:", error);
      setError("An unexpected error occurred");
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Now use fetchReports in useEffect
  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleSelectReport = (reportId) => {
    setSelectedReports((prev) => {
      if (prev.includes(reportId)) {
        return prev.filter((id) => id !== reportId);
      } else {
        return [...prev, reportId];
      }
    });
  };

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedReports(filteredReports.map((report) => report.id));
    } else {
      setSelectedReports([]);
    }
  };

  const handleExportReports = async () => {
    if (selectedReports.length === 0) {
      alert("Please select at least one report to export.");
      return;
    }

    try {
      await reportService.exportReports(selectedReports, "pdf", {});
      // Reset selected reports after export
      setSelectedReports([]);
    } catch (error) {
      console.error("Error exporting reports:", error);
      alert("Failed to export reports. Please try again.");
    }
  };

  const handleFilterChange = (e) => {
    setFilterStatus(e.target.value);
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleSortChange = (e) => {
    setSortOrder(e.target.value);
  };

  // Apply filters, search, and sorting
  const filteredReports = (Array.isArray(reports) ? reports : [])
    .filter((report) => {
      // Filter by status
      if (filterStatus !== "all" && report.status !== filterStatus) {
        return false;
      }

      // Search by target or name
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          (report.target_url &&
            report.target_url.toLowerCase().includes(query)) ||
          (report.name && report.name.toLowerCase().includes(query))
        );
      }

      return true;
    })
    .sort((a, b) => {
      // Sort by date
      if (sortOrder === "newest") {
        return new Date(b.created_at) - new Date(a.created_at);
      } else if (sortOrder === "oldest") {
        return new Date(a.created_at) - new Date(b.created_at);
      } else if (sortOrder === "severity") {
        // Sort by highest severity
        const severityOrder = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
          info: 0,
        };
        return (
          (severityOrder[b.highest_severity] || 0) -
          (severityOrder[a.highest_severity] || 0)
        );
      } else if (sortOrder === "score") {
        // Sort by security score (lowest first - worst security)
        return (a.security_score || 100) - (b.security_score || 100);
      }
      return 0;
    });

  if (loading) {
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
    <div className="container mt-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Security Reports</h1>
        <div className="d-flex">
          <button
            className="btn btn-primary me-2"
            onClick={handleExportReports}
            disabled={selectedReports.length === 0}
          >
            Download Selected PDFs ({selectedReports.length})
          </button>
          <Link to="/scans/new" className="btn btn-outline-primary">
            New Scan
          </Link>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}

      {/* Info about PDF-only reports */}
      <div className="alert alert-info mb-4">
        <div className="d-flex align-items-center">
          <i className="bi bi-info-circle me-2"></i>
          <span>
            Reports are generated from your completed scans. You can download
            PDF reports for any completed scan.
          </span>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <div className="row g-3">
            <div className="col-md-3">
              <label htmlFor="search" className="form-label">
                Search
              </label>
              <input
                type="text"
                className="form-control"
                id="search"
                placeholder="Search by target URL or name"
                value={searchQuery}
                onChange={handleSearchChange}
              />
            </div>
            <div className="col-md-3">
              <label htmlFor="filter" className="form-label">
                Filter by Status
              </label>
              <select
                className="form-select"
                id="filter"
                value={filterStatus}
                onChange={handleFilterChange}
              >
                <option value="all">All Reports</option>
                <option value="completed">Completed</option>
                <option value="in_progress">In Progress</option>
                <option value="pending">Pending</option>
                <option value="failed">Failed</option>
              </select>
            </div>
            <div className="col-md-3">
              <label htmlFor="sort" className="form-label">
                Sort by
              </label>
              <select
                className="form-select"
                id="sort"
                value={sortOrder}
                onChange={handleSortChange}
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="severity">Highest Severity</option>
                <option value="score">Lowest Security Score</option>
              </select>
            </div>
            <div className="col-md-3 d-flex align-items-end">
              <button
                className="btn btn-outline-secondary"
                onClick={fetchReports}
              >
                <i className="bi bi-arrow-clockwise me-1"></i>
                Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Reports List */}
      {filteredReports.length === 0 ? (
        <div className="alert alert-info">
          <div className="d-flex align-items-center justify-content-between">
            <span>
              {reports.length === 0
                ? "No reports found. Run a scan to generate security reports."
                : "No reports match your current filters. Try adjusting your search criteria."}
            </span>
            {reports.length === 0 && (
              <Link to="/scans/new" className="btn btn-sm btn-primary ms-3">
                Start New Scan
              </Link>
            )}
          </div>
        </div>
      ) : (
        <>
          <div className="mb-3">
            <div className="form-check">
              <input
                className="form-check-input"
                type="checkbox"
                id="selectAll"
                checked={
                  selectedReports.length === filteredReports.length &&
                  filteredReports.length > 0
                }
                onChange={handleSelectAll}
              />
              <label className="form-check-label" htmlFor="selectAll">
                Select All ({filteredReports.length} reports)
              </label>
            </div>
          </div>

          <div className="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4 mb-4">
            {filteredReports.map((report) => (
              <div className="col" key={`report-col-${report.id}`}>
                <ReportCard
                  key={`report-card-${report.id}`}
                  report={report}
                  isSelected={selectedReports.includes(report.id)}
                  onSelectReport={() => handleSelectReport(report.id)}
                />
              </div>
            ))}
          </div>

          {/* Summary stats */}
          <div className="row">
            <div className="col-12">
              <div className="card bg-light">
                <div className="card-body">
                  <div className="row text-center">
                    <div className="col-md-3">
                      <h5 className="text-primary">{reports.length}</h5>
                      <small className="text-muted">Total Scans</small>
                    </div>
                    <div className="col-md-3">
                      <h5 className="text-success">
                        {reports.filter((r) => r.status === "completed").length}
                      </h5>
                      <small className="text-muted">Completed</small>
                    </div>
                    <div className="col-md-3">
                      <h5 className="text-warning">
                        {
                          reports.filter((r) => r.status === "in_progress")
                            .length
                        }
                      </h5>
                      <small className="text-muted">In Progress</small>
                    </div>
                    <div className="col-md-3">
                      <h5 className="text-info">
                        {reports.filter((r) => r.status === "completed").length}
                      </h5>
                      <small className="text-muted">PDFs Available</small>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default ReportList;
