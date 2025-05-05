// frontend/src/pages/scans/ScanStatus.js

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { scanService } from '../../services/scanService';
import ScanProgress from '../../components/security/ScanProgress';
import VulnerabilityList from '../../components/reports/VulnerabilityList';

const ScanStatus = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Function to fetch scan data
  const fetchScan = useCallback(async () => {
    // Validate id parameter
    if (!id || id === 'undefined') {
      console.error('Invalid scan ID:', id);
      navigate('/dashboard');
      return;
    }
    
    try {
      const response = await scanService.getScan(id);
      
      if (response.success) {
        setScan(response.data);
        
        // If scan is completed, fetch results
        if (response.data.status === 'completed') {
          const resultsResponse = await scanService.getScanResults(id);
          if (resultsResponse.success) {
            setResults(resultsResponse.data.results || []);
          }
        }
      } else {
        setError('Failed to fetch scan data');
      }
    } catch (error) {
      console.error('Error fetching scan:', error);
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [id, navigate]);
  
  // Fetch scan data on component mount
  useEffect(() => {
    fetchScan();
  }, [fetchScan]);
  
  // Poll for updates if scan is in progress
  useEffect(() => {
    if (!scan || scan.status !== 'in_progress') return;
    
    const interval = setInterval(() => {
      fetchScan();
    }, 5000); // Poll every 5 seconds
    
    return () => clearInterval(interval);
  }, [scan, fetchScan]);
  
  // Handle scan cancellation
  const handleCancelScan = async () => {
    // Validate id before making API call
    if (!id || id === 'undefined') {
      setError('Invalid scan ID');
      return;
    }
    
    try {
      const response = await scanService.cancelScan(id);
      if (response.success) {
        fetchScan(); // Refresh scan data
      } else {
        setError('Failed to cancel scan');
      }
    } catch (error) {
      console.error('Error cancelling scan:', error);
      setError('An unexpected error occurred');
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
  
  if (!scan) {
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
          {scan.status === 'in_progress' && (
            <button 
              className="btn btn-danger" 
              onClick={handleCancelScan}
            >
              Cancel Scan
            </button>
          )}
        </div>
      </div>
      
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <h5 className="card-title">Target: {scan.target_url}</h5>
          <div className="row mt-3">
            <div className="col-md-6">
              <p><strong>Status:</strong> <span className={`badge ${getStatusBadgeClass(scan.status)}`}>{scan.status}</span></p>
              <p><strong>Scan Types:</strong> {scan.scan_types.join(', ')}</p>
              <p><strong>Created:</strong> {new Date(scan.created_at).toLocaleString()}</p>
            </div>
            <div className="col-md-6">
              {scan.started_at && (
                <p><strong>Started:</strong> {new Date(scan.started_at).toLocaleString()}</p>
              )}
              {scan.completed_at && (
                <p><strong>Completed:</strong> {new Date(scan.completed_at).toLocaleString()}</p>
              )}
              {scan.error_message && (
                <div className="alert alert-danger">
                  <strong>Error:</strong> {scan.error_message}
                </div>
              )}
            </div>
          </div>
          
          {scan.status === 'in_progress' && (
            <ScanProgress scanTypes={scan.scan_types} />
          )}
        </div>
      </div>
      
      {/* Results section - shown when scan is completed */}
      {scan.status === 'completed' && (
        <div className="card shadow-sm">
          <div className="card-body">
            <h5 className="card-title mb-4">Scan Results</h5>
            
            {results.length === 0 ? (
              <div className="alert alert-info">
                No issues found. Your site passed all security checks!
              </div>
            ) : (
              <VulnerabilityList results={results} />
            )}
            
            <div className="mt-4">
              <Link 
                to={`/reports/${id}`} 
                className="btn btn-primary"
              >
                View Full Report
              </Link>
            </div>
          </div>
        </div>
      )}
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

export default ScanStatus;