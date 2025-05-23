// frontend/src/pages/reports/SecurityReport.js

import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { reportService } from '../../services/reportService';
import VulnerabilityList from '../../components/reports/VulnerabilityList';
import AiRecommendations from '../../components/reports/AiRecommendations';
import { 
  getScoreColorClass, 
  getSeverityBadgeClass,
  getSecurityRating
} from '../../utils/securityUtils';

const SecurityReport = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [reportData, setReportData] = useState(null);
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
    
    const fetchReportData = async () => {
      try {
        setLoading(true);
        // Use the unified report service to get the report
        const response = await reportService.getReportById(id);
        
        if (response.success) {
          setReportData(response.data);
        } else {
          setError('Failed to fetch report data');
        }
      } catch (error) {
        console.error('Error fetching report data:', error);
        setError('An unexpected error occurred');
      } finally {
        setLoading(false);
      }
    };
    
    fetchReportData();
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
  
  if (!reportData) {
    return (
      <div className="container py-4">
        <div className="alert alert-warning" role="alert">
          Report not found
        </div>
      </div>
    );
  }
  
  const securityScore = reportData.security_score || 100;
  const severityCounts = reportData.findings_summary?.counts || {};
  const categoryCounts = reportData.category_counts || {};
  
  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Security Report</h2>
        <div className="d-flex">
          <Link to="/reports" className="btn btn-outline-secondary me-2">
            Back to Reports
          </Link>
          {reportData.status === 'completed' && (
            <button 
              className="btn btn-outline-primary"
              onClick={() => reportService.generatePdf(reportData.id, reportData.is_virtual)}
            >
              Download PDF
            </button>
          )}
        </div>
      </div>
      
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <div className="row">
            <div className="col-md-6">
              <h5 className="card-title">Target: {reportData.target_url}</h5>
              <p><strong>Scan Date:</strong> {new Date(reportData.completed_at || reportData.created_at).toLocaleString()}</p>
              <p><strong>Scan Types:</strong> {reportData.scan_types?.join(', ') || 'Full Scan'}</p>
            </div>
            <div className="col-md-6 text-md-end">
              <div className="d-inline-block text-center p-3 border rounded">
                <h6>Security Score</h6>
                <div className={`display-4 ${getScoreColorClass(securityScore)}`}>
                  {securityScore}
                </div>
                <div className="text-muted">
                  {getSecurityRating(securityScore)}
                </div>
              </div>
            </div>
          </div>
          
          <div className="row mt-4">
            <div className="col-12">
              <h6>Summary of Findings</h6>
              <div className="d-flex flex-wrap">
                {Object.entries(severityCounts).map(([severity, count]) => (
                  count > 0 && (
                    <div key={severity} className="me-3 mb-2">
                      <span className={`badge ${getSeverityBadgeClass(severity)} me-1`}>
                        {count}
                      </span>
                      <span className="text-capitalize">{severity}</span>
                    </div>
                  )
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
              {(!reportData.results || reportData.results.length === 0) ? (
                <div className="alert alert-info">
                  No vulnerabilities found. Your site passed all security checks!
                </div>
              ) : (
                <VulnerabilityList results={reportData.results} />
              )}
            </div>
          )}
          
          {activeTab === 'ai-recommendations' && (
            <div>
              <h5 className="card-title mb-4">AI-Powered Security Recommendations</h5>
              <AiRecommendations scanId={reportData.id} />
            </div>
          )}
          
          {activeTab === 'categories' && (
            <div>
              <h5 className="card-title mb-4">Findings by Category</h5>
              {(!categoryCounts || Object.keys(categoryCounts).length === 0) ? (
                <div className="alert alert-info">
                  No findings by category available.
                </div>
              ) : (
                <div className="list-group">
                  {Object.entries(categoryCounts).map(([category, count]) => {
                    // Get all results for this category
                    const categoryResults = reportData.results?.filter(result => 
                      result.category === category
                    ) || [];
                    
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

export default SecurityReport;