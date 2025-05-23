// frontend/src/components/reports/AiRecommendations.js

import React, { useState, useEffect, useRef } from 'react';
import { aiService } from '../../services/aiService';

// Helper function to get the correct badge class based on severity
const getSeverityBadgeClass = (severity) => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-danger';
    case 'high':
      return 'bg-warning';
    case 'medium':
      return 'bg-info';
    case 'low':
      return 'bg-success';
    default:
      return 'bg-secondary';
  }
};

const AiRecommendations = ({ scanId }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [analyses, setAnalyses] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisCompleted, setAnalysisCompleted] = useState(false);
  
  // Use useRef instead of state for the interval ID to avoid dependency cycles
  const pollingIntervalRef = useRef(null);
  const timeoutRef = useRef(null);
  
  // Separate effect to monitor analysis completion and clear intervals
  useEffect(() => {
    if (analysisCompleted) {
      console.log("Analysis completed, clearing polling intervals");
      
      // Clear polling interval when analysis is completed
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      
      // Clear timeout if it exists
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      
      // Set analyzing to false
      setAnalyzing(false);
    }
    
    // Cleanup on unmount or when dependencies change
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [analysisCompleted]);
  
  // Fetch existing AI analyses for this scan
  useEffect(() => {
    // Only fetch if scanId is valid
    if (!scanId || scanId === 'undefined') {
      setLoading(false);
      setError('Invalid scan ID');
      return;
    }
    
    const fetchAnalyses = async () => {
      try {
        const response = await aiService.getAnalysesForScan(scanId);
        
        if (response.success) {
          setAnalyses(response.data);
          
          // If there are analyses, fetch recommendations for the first one
          if (response.data.length > 0) {
            const recommendationsResponse = await aiService.getRecommendationsForAnalysis(response.data[0].id);
            if (recommendationsResponse.success) {
              setRecommendations(recommendationsResponse.data);
              
              // Set analysis completed if we have an analysis but no recommendations
              if (recommendationsResponse.data.length === 0) {
                setAnalysisCompleted(true);
              }
            }
          }
        } else {
          setError('Failed to fetch AI analyses');
        }
      } catch (error) {
        console.error('Error fetching AI analyses:', error);
        setError('An unexpected error occurred');
      } finally {
        setLoading(false);
      }
    };
    
    fetchAnalyses();
    
    // Clean up function for unmounting
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, [scanId]);
  
  // Function to check for analysis results
  const checkAnalysisResults = async () => {
    if (analysisCompleted) {
      // If analysis is already completed, don't poll anymore
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      return;
    }
    
    try {
      console.log("Checking analysis results...");
      const analysesResponse = await aiService.getAnalysesForScan(scanId);
      
      if (analysesResponse.success && analysesResponse.data.length > 0) {
        setAnalyses(analysesResponse.data);
        
        // Try to fetch recommendations
        const recommendationsResponse = await aiService.getRecommendationsForAnalysis(analysesResponse.data[0].id);
        
        if (recommendationsResponse.success) {
          setRecommendations(recommendationsResponse.data);
          
          // If we have recommendations or if it's been more than 30 seconds, consider it completed
          if (recommendationsResponse.data.length > 0 || 
              (analysesResponse.data[0].created_at && 
               (new Date() - new Date(analysesResponse.data[0].created_at)) > 30000)) {
            
            console.log("Setting analysis completed to true");
            setAnalysisCompleted(true);
          }
        }
      }
    } catch (error) {
      console.error('Error checking analysis results:', error);
    }
  };
  
  // Trigger AI analysis
  const handleRunAnalysis = async () => {
    // Validate scanId before making API call
    if (!scanId || scanId === 'undefined') {
      setError('Invalid scan ID');
      return;
    }
    
    // Clear any existing intervals
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    
    setAnalyzing(true);
    setError(''); // Clear any previous errors
    setAnalysisCompleted(false); // Reset completed state
    
    try {
      const response = await aiService.analyzeScan(scanId);
      
      if (response.success) {
        // Set up polling to check for results every 5 seconds
        pollingIntervalRef.current = setInterval(checkAnalysisResults, 5000);
        
        // Set a timeout to eventually stop polling after 3 minutes (prevent infinite polling)
        timeoutRef.current = setTimeout(() => {
          if (pollingIntervalRef.current) {
            clearInterval(pollingIntervalRef.current);
            pollingIntervalRef.current = null;
            
            // Only show error if we're still analyzing (no results came back)
            if (!analysisCompleted) {
              setAnalysisCompleted(true);
              setAnalyzing(false);
              setError('Analysis timed out. Please try again later.');
            }
          }
        }, 180000); // 3 minutes
      } else {
        setError('Failed to start AI analysis');
        setAnalyzing(false);
      }
    } catch (error) {
      console.error('Error starting AI analysis:', error);
      setError('An unexpected error occurred when starting the analysis');
      setAnalyzing(false);
    }
  };
  
  // Cancel analysis function
  const cancelAnalysis = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    
    setAnalyzing(false);
    setAnalysisCompleted(true);
  };
  
  // If scanId is invalid, show error message
  if (!scanId || scanId === 'undefined') {
    return (
      <div className="card">
        <div className="card-body text-center py-4">
          <h5 className="card-title mb-3">AI Security Analysis</h5>
          <div className="alert alert-warning" role="alert">
            Invalid scan ID. Please ensure you're viewing a valid scan report.
          </div>
        </div>
      </div>
    );
  }
  
  if (loading) {
    return (
      <div className="card">
        <div className="card-body">
          <h5 className="card-title mb-3">AI Security Analysis</h5>
          <div className="d-flex justify-content-center my-4">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          </div>
        </div>
      </div>
    );
  }
  
  // If no analyses exist yet, show the trigger button
  if (analyses.length === 0) {
    return (
      <div className="card">
        <div className="card-body text-center py-5">
          <h5 className="card-title mb-3">AI Security Analysis</h5>
          {error && (
            <div className="alert alert-danger mb-4" role="alert">
              {error}
            </div>
          )}
          <p className="card-text mb-4">
            Use our AI-powered analysis to get deeper insights and personalized recommendations
            based on your scan results.
          </p>
          <button
            className="btn btn-primary"
            onClick={handleRunAnalysis}
            disabled={analyzing}
          >
            {analyzing ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                Analyzing...
              </>
            ) : (
              'Run AI Analysis'
            )}
          </button>
        </div>
      </div>
    );
  }
  
  // If analyses exist but no recommendations AND analysis is completed, show the no issues message
  if (recommendations.length === 0 && analysisCompleted) {
    return (
      <div className="card">
        <div className="card-body py-4">
          <h5 className="card-title mb-3">AI Security Analysis</h5>
          <div className="alert alert-success" role="alert">
            <h6 className="alert-heading">Analysis Complete</h6>
            <p>No security issues were detected requiring recommendations.</p>
            <hr />
            <p className="mb-0">Your security scan did not identify any significant vulnerabilities or misconfigurations that need addressing at this time.</p>
          </div>
          <div className="text-center mt-4">
            <button
              className="btn btn-outline-primary"
              onClick={handleRunAnalysis}
              disabled={analyzing}
            >
              {analyzing ? 'Analyzing...' : 'Run New Analysis'}
            </button>
          </div>
        </div>
      </div>
    );
  }
  
  // If analyses exist but no recommendations and still waiting, show loading
  if (recommendations.length === 0) {
    return (
      <div className="card">
        <div className="card-body py-4">
          <h5 className="card-title mb-3">AI Security Analysis</h5>
          {error && (
            <div className="alert alert-danger mb-4" role="alert">
              {error}
            </div>
          )}
          <div className="d-flex justify-content-center my-4">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          </div>
          <p className="text-center">
            AI analysis in progress. This may take a few moments...
          </p>
          {analyzing && (
            <div className="text-center mt-3">
              <button 
                className="btn btn-sm btn-outline-secondary"
                onClick={cancelAnalysis}
              >
                Cancel Analysis
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }
  
  // Display recommendations
  return (
    <div className="card">
      <div className="card-body">
        <h5 className="card-title mb-3">AI Security Recommendations</h5>
        
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
        
        <div className="list-group">
          {recommendations.map((rec) => (
            <div key={rec.id} className="list-group-item list-group-item-action flex-column align-items-start">
              <div className="d-flex w-100 justify-content-between align-items-center mb-2">
                <h6 className="mb-0">{rec.title}</h6>
                <span className={`badge ${getSeverityBadgeClass(rec.severity)}`}>
                  {rec.severity}
                </span>
              </div>
              <p className="mb-2">{rec.description}</p>
              <div className="mt-2">
                <strong>Recommendation:</strong>
                <p className="mb-0">{rec.recommendation}</p>
              </div>
              <small className="text-muted mt-2">
                Confidence: {Math.round(rec.confidence_score * 100)}%
              </small>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AiRecommendations;