// Updated Dashboard.js with conditional rendering for Executive Summary

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import SecurityScoreCard from '../../components/dashboard/SecurityScoreCard';
import VulnerabilityChart from '../../components/dashboard/VulnerabilityChart';
import ScanHistoryTable from '../../components/security/ScanHistoryTable';
import AnomalyDetectionDashboard from '../../components/dashboard/AnomalyDetectionDashboard'; 
import ExecutiveSummary from '../../components/reports/ExecutiveSummary'; 
import AiRecommendations from '../../components/reports/AiRecommendations';
import { reportService } from '../../services/reportService';
import { scanService } from '../../services/scanService';
import { aiService } from '../../services/aiService'; // Import aiService

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [deleteSuccess, setDeleteSuccess] = useState('');
  const [executiveSummaryAvailable, setExecutiveSummaryAvailable] = useState(true);
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
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Use the unified report service to get reports
        const response = await reportService.getReports(true);
        
        if (response.success) {
          const reportData = response.data;
          
          // Also fetch scans for scan history table
          const scanResponse = await scanService.getScans();
          
          if (scanResponse.success) {
            const scanData = scanResponse.data.results || [];
            setScans(scanData);
            
            // Set the most recent scan as the selected scan
            if (scanData.length > 0) {
              setSelectedScanId(scanData[0].id);
              
              // Check if executive summary API is available
              try {
                const summaryResponse = await aiService.getExecutiveSummary(scanData[0].id);
                
                // If the API returns a 404 (notFound flag), hide the executive summary component
                if (summaryResponse.notFound) {
                  setExecutiveSummaryAvailable(false);
                }
              } catch (err) {
                if (err?.response?.status === 404) {
                  setExecutiveSummaryAvailable(false);
                }
              }
            }
          }
          
          // Get security metrics from the LATEST report instead of averaging
          if (reportData.length > 0) {
            // Sort reports by date (descending) to get the latest first
            const sortedReports = [...reportData].sort((a, b) => 
              new Date(b.created_at) - new Date(a.created_at)
            );
            
            // Get the most recent report
            const latestReport = sortedReports[0];
            
            // Get vulnerability counts from latest report
            const vulnerabilityCounts = 
              latestReport.findings_summary?.counts || 
              { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            
            // Use the security score directly from the latest report
            const latestScore = latestReport.security_score || 100;
            
            // Update security metrics with data from the latest report only
            setSecurityMetrics({
              overallScore: latestScore,
              categoryScores: {
                headers: latestReport.category_scores?.headers || 100,
                ssl: latestReport.category_scores?.ssl || 100,
                vulnerabilities: latestReport.category_scores?.vulnerabilities || 100,
                content: latestReport.category_scores?.content || 100
              },
              vulnerabilityCounts: vulnerabilityCounts,
              totalScans: reportData.length
            });
          }
        } else {
          setError(typeof response.error === 'string' ? 
            response.error : 'Failed to fetch scan data');
        }
      } catch (error) {
        console.error('Error fetching data:', error);
        setError(typeof error === 'string' ? 
          error : (error?.message || 'An unexpected error occurred'));
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, []);
  
  const handleDeleteScan = async (scanId) => {
    try {
      // Clear any previous success messages
      setDeleteSuccess('');
      
      const response = await scanService.deleteScan(scanId);
      
      if (response.success) {
        // Remove the deleted scan from the list
        setScans(scans.filter(scan => scan.id !== scanId));
        
        // Show success message
        setDeleteSuccess('Scan deleted successfully');
        
        // Clear the selected scan if it was the one that was deleted
        if (selectedScanId === scanId) {
          setSelectedScanId(null);
        }
        
        // Clear success message after 3 seconds
        setTimeout(() => {
          setDeleteSuccess('');
        }, 3000);
      } else {
        setError(typeof response.error === 'string' ? 
          response.error : 'Failed to delete scan');
      }
      
      return response;
    } catch (error) {
      console.error('Error deleting scan:', error);
      setError(typeof error === 'string' ? 
        error : (error?.message || 'An unexpected error occurred while deleting the scan'));
      throw error;
    }
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
      
      {deleteSuccess && (
        <div className="alert alert-success" role="alert">
          {deleteSuccess}
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
      
      {/* Conditionally render Executive Summary based on API availability */}
      {selectedScanId && executiveSummaryAvailable && (
        <ExecutiveSummary scanId={selectedScanId} />
      )}
      
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
            onDeleteScan={handleDeleteScan}
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
      
      {/* Add AI Recommendations if a scan is selected */}
      {selectedScanId && (
        <div className="mt-4">
          <AiRecommendations scanId={selectedScanId} />
        </div>
      )}
    </div>
  );
};

export default Dashboard;