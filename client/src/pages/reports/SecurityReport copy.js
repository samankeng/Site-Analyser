// frontend/src/pages/reports/SecurityReport.js

import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { scanService } from '../../services/scanService';
import VulnerabilityList from '../../components/reports/VulnerabilityList';
import AiRecommendations from '../../components/reports/AiRecommendations';

const SecurityReport = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  
  useEffect(() => {
    // Validate id parameter
    if (!id || id === 'undefined') {
      console.error('Invalid report ID:', id);
      navigate('/reports');
      return;
    }
    
    const fetchScanData = async () => {
      try {
        // Fetch scan details
        const scanResponse = await scanService.getScan(id);
        
        if (scanResponse.success) {
          setScan(scanResponse.data);
          
          // Fetch scan results
          const resultsResponse = await scanService.getScanResults(id);
          if (resultsResponse.success) {
            setResults(resultsResponse.data.results || []);
          }
        } else {
          setError('Failed to fetch scan data');
        }
      } catch (error) {
        console.error('Error fetching scan data:', error);
        setError('An unexpected error occurred');
      } finally {
        setLoading(false);
      }
    };
    
    fetchScanData();
  }, [id, navigate]);
  
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
          Report not found
        </div>
      </div>
    );
  }
  
  // Count findings by severity
  const severityCounts = results.reduce((acc, result) => {
    acc[result.severity] = (acc[result.severity] || 0) + 1;
    return acc;
  }, {});
  
  // Count findings by category
  const categoryCounts = results.reduce((acc, result) => {
    acc[result.category] = (acc[result.category] || 0) + 1;
    return acc;
  }, {});
  
  // Calculate security score (simplified)
  const calculateSecurityScore = () => {
    // Start with a perfect score
    let score = 100;
    
    // Deduct points based on severity
    score -= (severityCounts.critical || 0) * 20;
    score -= (severityCounts.high || 0) * 10;
    score -= (severityCounts.medium || 0) * 5;
    score -= (severityCounts.low || 0) * 2;
    
    // Ensure score is between 0 and 100
    return Math.max(0, Math.min(100, score));
  };
  
  const securityScore = calculateSecurityScore();
  
  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Security Report</h2>
        <Link to="/reports" className="btn btn-outline-secondary">
          Back to Reports
        </Link>
      </div>
      
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <h5 className="card-title">Target: {scan.target_url}</h5>
              <p><strong>Scan Date:</strong> {new Date(scan.completed_at).toLocaleString()}</p>
              <p><strong>Scan Types:</strong> {scan.scan_types.join(', ')}</p>
            </div>
            <div className="col-md-6 text-md-end">
              <div className="d-inline-block text-center p-3 border rounded">
                <h6>Security Score</h6>
                <div className={`display-4 ${getScoreColorClass(securityScore)}`}>{securityScore}</div>
                <div className="text-muted">out of 100</div>
              </div>
            </div>
          </div>
          
          <div className="row mt-4">
            <div className="col-12">
              <h6>Summary of Findings</h6>
              <div className="d-flex flex-wrap">
                {Object.entries(severityCounts).map(([severity, count]) => (
                  <div key={severity} className="me-3 mb-2">
                    <span className={`badge ${getSeverityBadgeClass(severity)} me-1`}>{count}</span>
                    <span className="text-capitalize">{severity}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div className="card shadow-sm">
        <div className="card-header">
          <ul className="nav nav-tabs card-header-tabs">
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
                onClick={() => setActiveTab('vulnerabilities')}
              >
                Vulnerabilities
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'ai-recommendations' ? 'active' : ''}`}
                onClick={() => setActiveTab('ai-recommendations')}
              >
                AI Recommendations
              </button>
            </li>
            <li className="nav-item">
              <button
                className={`nav-link ${activeTab === 'categories' ? 'active' : ''}`}
                onClick={() => setActiveTab('categories')}
              >
                Categories
              </button>
            </li>
          </ul>
        </div>
        <div className="card-body">
          {activeTab === 'vulnerabilities' && (
            <div>
              <h5 className="card-title mb-4">Vulnerability Findings</h5>
              {results.length === 0 ? (
                <div className="alert alert-info">
                  No vulnerabilities found. Your site passed all security checks!
                </div>
              ) : (
                <VulnerabilityList results={results} />
              )}
            </div>
          )}
          
          {activeTab === 'ai-recommendations' && (
            <div>
              <h5 className="card-title mb-4">AI-Powered Security Recommendations</h5>
              {/* Pass actual scan.id instead of using URL parameter directly */}
              <AiRecommendations scanId={scan.id} />
            </div>
          )}
          
          {activeTab === 'categories' && (
            <div>
              <h5 className="card-title mb-4">Findings by Category</h5>
              {Object.keys(categoryCounts).length === 0 ? (
                <div className="alert alert-info">
                  No findings by category available.
                </div>
              ) : (
                <div className="list-group">
                  {Object.entries(categoryCounts).map(([category, count]) => {
                    // Get all results for this category
                    const categoryResults = results.filter(result => result.category === category);
                    
                    return (
                      <div key={category} className="list-group-item">
                        <div className="d-flex justify-content-between align-items-center mb-2">
                          <h6 className="mb-0 text-capitalize">{category}</h6>
                          <span className="badge bg-secondary">{count}</span>
                        </div>
                        <div>
                          <button
                            className="btn btn-sm btn-outline-primary"
                            data-bs-toggle="collapse"
                            data-bs-target={`#category-${category}`}
                            aria-expanded="false"
                            aria-controls={`category-${category}`}
                          >
                            Show Details
                          </button>
                          <div className="collapse mt-3" id={`category-${category}`}>
                            <VulnerabilityList results={categoryResults} />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// Helper function for severity badge color
const getSeverityBadgeClass = (severity) => {
  switch (severity) {
    case 'critical':
      return 'bg-danger';
    case 'high':
      return 'bg-warning text-dark';
    case 'medium':
      return 'bg-info text-dark';
    case 'low':
      return 'bg-secondary';
    case 'info':
      return 'bg-light text-dark';
    default:
      return 'bg-secondary';
  }
};

// Helper function for score color
const getScoreColorClass = (score) => {
  if (score >= 90) return 'text-success';
  if (score >= 70) return 'text-info';
  if (score >= 50) return 'text-warning';
  return 'text-danger';
};

export default SecurityReport;