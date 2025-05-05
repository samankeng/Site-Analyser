// frontend/src/components/security/ScanHistoryTable.js

import React from 'react';
import { Link } from 'react-router-dom';

const ScanHistoryTable = ({ scans, loading }) => {
  if (loading) {
    return (
      <div className="d-flex justify-content-center my-4">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }
  
  if (scans.length === 0) {
    return (
      <div className="alert alert-info" role="alert">
        No scan history found. Start a new scan to see results here.
      </div>
    );
  }
  
  return (
    <div className="table-responsive">
      <table className="table table-hover">
        <thead>
          <tr>
            <th>Target URL</th>
            <th>Scan Types</th>
            <th>Status</th>
            <th>Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="text-truncate" style={{ maxWidth: '200px' }}>
                {scan.target_url}
              </td>
              <td>
                {scan.scan_types.map((type) => (
                  <span key={type} className="badge bg-secondary me-1">
                    {type}
                  </span>
                ))}
              </td>
              <td>
                <span className={`badge ${getStatusBadgeClass(scan.status)}`}>
                  {scan.status}
                </span>
              </td>
              <td>{new Date(scan.created_at).toLocaleString()}</td>
              <td>
                <Link to={`/scans/${scan.id}`} className="btn btn-sm btn-outline-primary">
                  View
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Helper function for status badge color
const getStatusBadgeClass = (status) => {
  switch (status) {
    case 'completed':
      return 'bg-success';
    case 'pending':
      return 'bg-warning text-dark';
    case 'in_progress':
      return 'bg-info text-dark';
    case 'failed':
      return 'bg-danger';
    default:
      return 'bg-secondary';
  }
};

export default ScanHistoryTable;