// frontend/src/pages/dashboard/Dashboard.js

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import SecurityScoreCard from '../../components/dashboard/SecurityScoreCard';
import VulnerabilityChart from '../../components/dashboard/VulnerabilityChart';
import ScanHistoryTable from '../../components/security/ScanHistoryTable';
import AnomalyDetectionDashboard from '../../components/dashboard/AnomalyDetectionDashboard';
import { scanService } from '../../services/scanService';
import { prepareDashboardMetrics } from '../../models/ScanResultsModel';

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [securityMetrics, setSecurityMetrics] = useState({
    overallScore: 100,
    categoryScores: {
      headers: 100,
      ssl: 100,
      vulnerabilities: 100,
      content: 100
    },
    vulnerabilityCounts: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    totalScans: 0
  });
  
  useEffect(() => {
    const fetchScans = async () => {
      try {
        setLoading(true);
        const response = await scanService.getScans();
        
        if (response.success) {
          const scanData = response.data.results || [];
          setScans(scanData);
          
          // Set the most recent scan as the selected scan
          if (scanData.length > 0) {
            setSelectedScanId(scanData[0].id);
          }
          
          // Calculate security metrics
          const metrics = prepareDashboardMetrics(scanData);
          setSecurityMetrics(metrics);
        } else {
          setError('Failed to fetch scan data');
        }
      } catch (error) {
        console.error('Error fetching scans:', error);
        setError('An unexpected error occurred');
      } finally {
        setLoading(false);
      }
    };
    
    fetchScans();
  }, []);
  
  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Dashboard</h2>
        <Link to="/scans/new" className="btn btn-primary">
          New Scan
        </Link>
      </div>
      
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      
      <div className="row g-4 mb-4">
        <div className="col-md-6">
          <SecurityScoreCard 
            score={securityMetrics.overallScore} 
            categories={securityMetrics.categoryScores} 
          />
        </div>
        <div className="col-md-6">
          <VulnerabilityChart 
            vulnerabilities={securityMetrics.vulnerabilityCounts} 
          />
        </div>
      </div>
      
      <div className="card shadow-sm">
        <div className="card-body">
          <div className="d-flex justify-content-between align-items-center mb-3">
            <h5 className="card-title mb-0">Recent Scans</h5>
            <Link to="/reports" className="btn btn-sm btn-outline-primary">
              View All Reports
            </Link>
          </div>
          
          <ScanHistoryTable 
            scans={scans} 
            loading={loading}
            onSelectScan={(scanId) => setSelectedScanId(scanId)} 
          />
        </div>
      </div>
      
      {/* Only show anomaly detection if we have a selected scan */}
      {selectedScanId && (
        <div className="card shadow-sm mt-4">
          <div className="card-body">
            <AnomalyDetectionDashboard scanId={selectedScanId} />
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;