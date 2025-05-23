// frontend/src/components/reports/ReportList.js

import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { reportService } from '../../services/reportService';
import ReportCard from './ReportCard';
import ReportExport from './ReportExport';

const ReportList = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedReports, setSelectedReports] = useState([]);
  const [showExportModal, setShowExportModal] = useState(false);
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortOrder, setSortOrder] = useState('newest');
  const [useVirtualReports, setUseVirtualReports] = useState(true);

  // Define fetchReports using useCallback before using it in useEffect
  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError('');
    
    try {
      // Use the unified report service to fetch reports
      const response = await reportService.getReports(useVirtualReports);
      
      if (response.success) {
        setReports(Array.isArray(response.data) ? response.data : []);
      } else {
        setError(response.error || 'Failed to fetch reports');
        setReports([]);
      }
    } catch (error) {
      console.error('Error fetching reports:', error);
      setError('An unexpected error occurred');
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, [useVirtualReports]);

  // Now use fetchReports in useEffect
  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleSelectReport = (reportId) => {
    setSelectedReports(prev => {
      if (prev.includes(reportId)) {
        return prev.filter(id => id !== reportId);
      } else {
        return [...prev, reportId];
      }
    });
  };

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedReports(filteredReports.map(report => report.id));
    } else {
      setSelectedReports([]);
    }
  };

  const handleExportClick = () => {
    setShowExportModal(true);
  };

  const handleCloseExportModal = () => {
    setShowExportModal(false);
  };

  const handleExportReports = async (format, options) => {
    try {
      await reportService.exportReports(selectedReports, format, options, useVirtualReports);
      setShowExportModal(false);
      // Reset selected reports after export
      setSelectedReports([]);
    } catch (error) {
      console.error('Error exporting reports:', error);
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

  const toggleReportMode = () => {
    setUseVirtualReports(!useVirtualReports);
  };

  // Apply filters, search, and sorting
  const filteredReports = (Array.isArray(reports) ? reports : [])
    .filter(report => {
      // Filter by status
      if (filterStatus !== 'all' && report.status !== filterStatus) {
        return false;
      }
      
      // Search by target or name
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          (report.target_url && report.target_url.toLowerCase().includes(query)) ||
          (report.name && report.name.toLowerCase().includes(query))
        );
      }
      
      return true;
    })
    .sort((a, b) => {
      // Sort by date
      if (sortOrder === 'newest') {
        return new Date(b.created_at) - new Date(a.created_at);
      } else if (sortOrder === 'oldest') {
        return new Date(a.created_at) - new Date(b.created_at);
      } else if (sortOrder === 'severity') {
        // Sort by highest severity
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        return (severityOrder[b.highest_severity] || 0) - (severityOrder[a.highest_severity] || 0);
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
            onClick={handleExportClick}
            disabled={selectedReports.length === 0}
          >
            Export Selected
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

      {/* Report Type Toggle */}
      <div className="card shadow-sm mb-3">
        <div className="card-body">
          <div className="form-check form-switch">
            <input
              className="form-check-input"
              type="checkbox"
              id="reportModeSwitch"
              checked={useVirtualReports}
              onChange={toggleReportMode}
            />
            <label className="form-check-label" htmlFor="reportModeSwitch">
              {useVirtualReports ? "Using virtual reports (from scans)" : "Using saved reports"}
            </label>
          </div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <div className="row g-3">
            <div className="col-md-4">
              <label htmlFor="search" className="form-label">Search</label>
              <input
                type="text"
                className="form-control"
                id="search"
                placeholder="Search by target URL or name"
                value={searchQuery}
                onChange={handleSearchChange}
              />
            </div>
            <div className="col-md-4">
              <label htmlFor="filter" className="form-label">Filter by Status</label>
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
            <div className="col-md-4">
              <label htmlFor="sort" className="form-label">Sort by</label>
              <select 
                className="form-select" 
                id="sort"
                value={sortOrder}
                onChange={handleSortChange}
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="severity">Highest Severity</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Reports List */}
      {filteredReports.length === 0 ? (
        <div className="alert alert-info">
          <div className="d-flex align-items-center">
            <span>
              No reports found. {reports.length > 0 ? "Try adjusting your filters." : "Run a scan to generate security reports."}
            </span>
            {reports.length === 0 && (
              <button
                className="btn btn-sm btn-primary ms-3"
                onClick={fetchReports}
              >
                Refresh Reports
              </button>
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
                checked={selectedReports.length === filteredReports.length && filteredReports.length > 0}
                onChange={handleSelectAll}
              />
              <label className="form-check-label" htmlFor="selectAll">
                Select All ({filteredReports.length} reports)
              </label>
            </div>
          </div>

          <div className="row row-cols-1 row-cols-md-2 g-4 mb-4">
            {filteredReports.map(report => (
              <div className="col" key={report.id}>
                <ReportCard 
                  report={report} 
                  isSelected={selectedReports.includes(report.id)}
                  onSelectReport={() => handleSelectReport(report.id)}
                />
              </div>
            ))}
          </div>
        </>
      )}

      {/* Export Modal */}
      <ReportExport 
        show={showExportModal}
        onClose={handleCloseExportModal}
        onExport={handleExportReports}
        selectedCount={selectedReports.length}
      />
    </div>
  );
};

export default ReportList;