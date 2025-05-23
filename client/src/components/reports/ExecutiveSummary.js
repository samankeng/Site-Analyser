// Updated Executive Summary component that handles missing endpoints gracefully

import React, { useState, useEffect } from 'react';
import { aiService } from '../../services/aiService';

const ExecutiveSummary = ({ scanId }) => {
  const [summary, setSummary] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [analysisId, setAnalysisId] = useState(null);
  const [apiAvailable, setApiAvailable] = useState(true);

  useEffect(() => {
    const fetchSummary = async () => {
      if (!scanId || scanId === 'undefined') {
        setError('Invalid scan ID');
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        console.log(`Fetching executive summary for scan: ${scanId}`);
        const response = await aiService.getExecutiveSummary(scanId);
        
        if (response && response.success) {
          console.log('Executive summary fetched successfully:', response.data);
          
          // Ensure the summary is a string
          const summaryText = typeof response.data?.summary === 'string' 
            ? response.data.summary 
            : '';
            
          setSummary(summaryText);
          
          // Check that analysisId is a string before setting it
          if (typeof response.data?.analysisId === 'string') {
            setAnalysisId(response.data.analysisId);
          }
        } else {
          console.warn('Failed to fetch executive summary:', response?.error);
          
          // Check if the API is simply not available
          if (response?.notFound) {
            setApiAvailable(false);
            console.log('Executive summary endpoint not available - hiding component');
          } else {
            // Other error - show to the user
            setError(typeof response?.error === 'string' ? 
              response.error : 'Failed to load executive summary');
          }
        }
      } catch (err) {
        console.error('Error fetching executive summary:', err);
        
        // Check for 404 errors specifically
        if (err?.response?.status === 404) {
          setApiAvailable(false);
        } else {
          setError(err?.message || 'An unexpected error occurred');
        }
      } finally {
        setLoading(false);
      }
    };

    fetchSummary();
  }, [scanId]);

  // Format the summary text with line breaks preserved
  const formatSummary = (text) => {
    if (!text) return null;
    
    // Ensure text is a string before trying to split it
    if (typeof text !== 'string') {
      return <p>Summary is not available in the expected format.</p>;
    }
    
    return text.split('\n\n').map((paragraph, index) => (
      <p key={index} className="mb-2">{paragraph}</p>
    ));
  };

  // If API is not available, don't show the component at all
  if (!apiAvailable) {
    return null;
  }

  if (loading) {
    return (
      <div className="card mb-4">
        <div className="card-body">
          <h5 className="card-title mb-3">Executive Summary</h5>
          <div className="d-flex justify-content-center my-4">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card mb-4">
        <div className="card-body">
          <h5 className="card-title mb-3">Executive Summary</h5>
          <div className="alert alert-danger" role="alert">
            {typeof error === 'string' ? error : 'An error occurred while loading the summary.'}
          </div>
        </div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="card mb-4">
        <div className="card-body">
          <h5 className="card-title mb-3">Executive Summary</h5>
          <div className="alert alert-info" role="alert">
            No executive summary is available for this scan. Try running an AI analysis first.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card mb-4">
      <div className="card-body">
        <h5 className="card-title mb-3">Executive Summary</h5>
        <div className="card-text">
          {formatSummary(summary)}
        </div>
        {analysisId && (
          <div className="d-flex justify-content-end mt-3">
            <small className="text-muted">
              Analysis ID: {analysisId}
            </small>
          </div>
        )}
      </div>
    </div>
  );
};

export default ExecutiveSummary;