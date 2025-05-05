// frontend/src/pages/dashboard/Dashboard.js

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import SecurityScoreCard from '../../components/dashboard/SecurityScoreCard';
import VulnerabilityChart from '../../components/dashboard/VulnerabilityChart';
import ScanHistoryTable from '../../components/security/ScanHistoryTable';
import AnomalyDetectionDashboard from '../../components/dashboard/AnomalyDetectionDashboard';
import { scanService } from '../../services/scanService';


const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedScanId, setSelectedScanId] = useState(null);
  
  // Security metrics (these would be calculated based on scan results in a real implementation)
  const [securityMetrics, setSecurityMetrics] = useState({
    overallScore: 0,
    categoryScores: {},
    vulnerabilityCounts: {},
    totalScans: 0,
  });
  
  useEffect(() => {
    const fetchScans = async () => {
      try {
        const response = await scanService.getScans();
        
        if (response.success) {
          const scanData = response.data.results || [];
          setScans(scanData);
          
          // Set the most recent scan as the selected scan
          if (scanData.length > 0) {
            setSelectedScanId(scanData[0].id);
          }
          
          // Calculate security metrics
          calculateSecurityMetrics(scanData);
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
  
  const calculateSecurityMetrics = (scanData) => {
    // In a real implementation, this would be more sophisticated
    
    // Set default metrics
    const metrics = {
      overallScore: 100, // Default score
      categoryScores: {
        headers: 80,
        ssl: 90,
        vulnerabilities: 75,
        content: 95,
      },
      vulnerabilityCounts: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      totalScans: scanData.length,
    };
    
    // Count vulnerabilities by severity
    // In a real implementation, this would analyze actual scan results
    if (scanData.length > 0) {
      // This is simplified example logic - in reality, you'd aggregate from actual scan results
      for (const scan of scanData) {
        if (scan.results && scan.results.length > 0) {
          for (const result of scan.results) {
            if (result.severity in metrics.vulnerabilityCounts) {
              metrics.vulnerabilityCounts[result.severity]++;
            }
          }
        }
      }
      
      const totalVulnerabilities = Object.values(metrics.vulnerabilityCounts).reduce((a, b) => a + b, 0);
      // Adjust overall score based on vulnerabilities
      // const totalVulnerabilities = Object.values(metrics.vulnerabilityCounts).reduce((a, b) => a + b, 0);
      // const criticalFactor = metrics.vulnerabilityCounts.critical * 10;
      // const highFactor = metrics.vulnerabilityCounts.high * 5;
      // const mediumFactor = metrics.vulnerabilityCounts.medium * 2;

      metrics.overallScore = 100;
      metrics.overallScore -= (metrics.vulnerabilityCounts.critical || 0) * 20;
      metrics.overallScore -= (metrics.vulnerabilityCounts.high || 0) * 10;
      metrics.overallScore -= (metrics.vulnerabilityCounts.medium || 0) * 5;
      metrics.overallScore -= (metrics.vulnerabilityCounts.low || 0) * 2;
      
      // Simple formula to adjust score based on vulnerabilities
      if (totalVulnerabilities > 0) {
        metrics.overallScore = Math.max(0, Math.min(100, metrics.overallScore));
      }
    }
    
    setSecurityMetrics(metrics);
  };
  
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
            onSelectScan={(scanId) => setSelectedScanId(scanId)} // Add this if you want to allow selection
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
