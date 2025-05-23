// Update AnomalyDetectionDashboard.js
import React, { useState, useEffect } from 'react';
import anomalyService from '../../services/anomalyService';

const AnomalyDetectionDashboard = ({ scanId }) => {
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  useEffect(() => {
    const fetchAnomalies = async () => {
      if (!scanId) {
        setLoading(false);
        return;
      }
      
      try {
        const response = await anomalyService.getAnomaliesForScan(scanId);
        if (response.success) {
          // Make sure we're setting an array, even if the API returns something else
          setAnomalies(Array.isArray(response.data) ? response.data : []);
        } else {
          setError(response.error || 'Failed to fetch anomalies');
          setAnomalies([]);
        }
      } catch (error) {
        console.error('Error fetching anomalies:', error);
        setError('An unexpected error occurred');
        setAnomalies([]);
      } finally {
        setLoading(false);
      }
    };
    
    fetchAnomalies();
  }, [scanId]);
  
  if (!scanId) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5>Anomaly Detection</h5>
        <p className="text-muted">Select a scan to view anomalies.</p>
      </div>
    );
  }
  
  if (loading) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5>Anomaly Detection</h5>
        <div className="d-flex justify-content-center my-4">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
        </div>
      </div>
    );
  }
  
  if (error) {
    return (
      <div className="anomaly-dashboard p-3">
        <h5>Anomaly Detection</h5>
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      </div>
    );
  }
  
  return (
    <div className="anomaly-dashboard p-3">
      <h5>Anomaly Detection</h5>
      {anomalies.length === 0 ? (
        <p className="text-muted">No anomalies detected for this scan.</p>
      ) : (
        <div className="anomaly-list">
          {anomalies.map((anomaly, index) => (
            <div key={index} className={`anomaly-item card mb-3 border-${getSeverityClass(anomaly.severity)}`}>
              <div className={`card-header bg-transparent border-${getSeverityClass(anomaly.severity)}`}>
                <div className="d-flex justify-content-between align-items-center">
                  <h6 className="mb-0">{anomaly.component}</h6>
                  <span className={`badge bg-${getSeverityClass(anomaly.severity)}`}>
                    {anomaly.severity}
                  </span>
                </div>
              </div>
              <div className="card-body">
                <p className="card-text">{anomaly.description}</p>
                {anomaly.recommendation && (
                  <div className="mt-2">
                    <strong>Recommendation:</strong>
                    <p className="mb-0">{anomaly.recommendation}</p>
                  </div>
                )}
                <div className="mt-2 d-flex justify-content-between">
                  <small className="text-muted">
                    Anomaly Score: {(anomaly.score * 100).toFixed(1)}%
                  </small>
                  {anomaly.is_false_positive && (
                    <span className="badge bg-secondary">False Positive</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Helper function to get Bootstrap color class based on severity
const getSeverityClass = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'secondary';
  }
};

export default AnomalyDetectionDashboard;