// frontend/src/components/security/ScanHistoryTable.js

import React from 'react';
import { Link } from 'react-router-dom';
import { getStatusBadgeClass, getSeverityBadgeClass } from '../../utils/securityUtils';

const ScanHistoryTable = ({ scans, loading, onSelectScan }) => {
  if (loading) {
    return (
      <div className="d-flex justify-content-center my-4">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }
  
  if (!scans || scans.length === 0) {
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
            <th>Findings</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} onClick={() => onSelectScan && onSelectScan(scan.id)} style={{ cursor: 'pointer' }}>
              <td className="text-truncate" style={{ maxWidth: '200px' }}>
                {scan.target_url}
              </td>
              <td>
                {scan.scan_types && scan.scan_types.map((type) => (
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
                {scan.severityCounts && Object.entries(scan.severityCounts).map(([severity, count]) => (
                  count > 0 && (
                    <span key={severity} className={`badge ${getSeverityBadgeClass(severity)} me-1`}>
                      {count} {severity}
                    </span>
                  )
                ))}
              </td>
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

export default ScanHistoryTable;