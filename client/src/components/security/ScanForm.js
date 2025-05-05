// frontend/src/components/security/ScanForm.js

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanService } from '../../services/scanService';

const ScanForm = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [scanTypes, setScanTypes] = useState({
    headers: true,
    ssl: true,
    vulnerabilities: true,
    content: false,
    ports: false,
    csp: true,
    cookies: false,
    cors: false,
    server: false
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  
  // Available scan types with details
  const availableScanTypes = [
    {
      id: 'headers',
      name: 'HTTP Headers Analysis',
      description: 'Examines HTTP headers for missing security headers',
      category: 'Web Security',
      icon: '🛡️'
    },
    {
      id: 'ssl',
      name: 'SSL/TLS Configuration',
      description: 'Validates certificate and checks for TLS vulnerabilities',
      category: 'Web Security',
      icon: '🔒'
    },
    {
      id: 'vulnerabilities',
      name: 'Vulnerability Scan',
      description: 'Detects common web vulnerabilities and misconfigurations',
      category: 'Web Security',
      icon: '⚠️'
    },
    {
      id: 'content',
      name: 'Content Analysis',
      description: 'Analyzes page content for SEO and security issues',
      category: 'Content Quality',
      icon: '📄'
    },
    {
      id: 'ports',
      name: 'Port Scanning',
      description: 'Checks for open ports and services on the target',
      category: 'Infrastructure',
      icon: '🖥️'
    },
    {
      id: 'csp',
      name: 'Content Security Policy',
      description: 'Evaluates CSP headers to prevent XSS attacks',
      category: 'Web Security',
      icon: '🛡️'
    },
    {
      id: 'cookies',
      name: 'Cookie Security',
      description: 'Analyzes cookies for security issues and proper configuration',
      category: 'Web Security',
      icon: '🍪'
    },
    {
      id: 'cors',
      name: 'CORS Configuration',
      description: 'Checks Cross-Origin Resource Sharing settings for vulnerabilities',
      category: 'Web Security',
      icon: '🔄'
    },
    {
      id: 'server',
      name: 'Server Analysis',
      description: 'Examines server configuration and information disclosure',
      category: 'Infrastructure',
      icon: '🖧'
    }
  ];
  
  // Group scan types by category
  const scanTypesByCategory = availableScanTypes.reduce((acc, scanType) => {
    if (!acc[scanType.category]) {
      acc[scanType.category] = [];
    }
    acc[scanType.category].push(scanType);
    return acc;
  }, {});
  
  const handleCheckboxChange = (e) => {
    const { name, checked } = e.target;
    setScanTypes(prev => ({ ...prev, [name]: checked }));
  };
  
  const selectAllScanTypes = () => {
    const allSelected = Object.keys(scanTypes).every(type => scanTypes[type]);
    
    const updatedScanTypes = {};
    Object.keys(scanTypes).forEach(type => {
      updatedScanTypes[type] = !allSelected;
    });
    
    setScanTypes(updatedScanTypes);
  };
  
  const selectCategoryTypes = (category) => {
    // Get all scan types in this category
    const categoryTypes = scanTypesByCategory[category].map(type => type.id);
    
    // Check if all types in this category are already selected
    const allCategorySelected = categoryTypes.every(type => scanTypes[type]);
    
    // Update scan types in this category
    const updatedScanTypes = { ...scanTypes };
    categoryTypes.forEach(type => {
      updatedScanTypes[type] = !allCategorySelected;
    });
    
    setScanTypes(updatedScanTypes);
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Basic URL validation
    if (!url) {
      setError('Please enter a URL to scan');
      return;
    }
    
    // Add protocol if missing
    let targetUrl = url;
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl;
    }
    
    // At least one scan type must be selected
    const selectedTypes = Object.keys(scanTypes).filter(type => scanTypes[type]);
    if (selectedTypes.length === 0) {
      setError('Please select at least one scan type');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      const scanData = {
        target_url: targetUrl,
        scan_types: selectedTypes
      };
      
      const response = await scanService.createScan(scanData);
      
      if (response.success) {
        // Redirect to scan status page
        navigate(`/scans/${response.data.id}`);
      } else {
        setError(response.error?.non_field_errors || 'Failed to create scan. Please try again.');
      }
    } catch (error) {
      setError('An unexpected error occurred. Please try again.');
      console.error('Scan creation error:', error);
    } finally {
      setLoading(false);
    }
  };
  
  // Calculate how many scan types are selected
  const selectedCount = Object.values(scanTypes).filter(Boolean).length;
  const totalCount = Object.keys(scanTypes).length;
  const allSelected = selectedCount === totalCount;
  
  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <h5 className="card-title mb-4">New Security Scan</h5>
        
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="url" className="form-label">Target URL</label>
            <input
              type="text"
              className="form-control"
              id="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <div className="form-text">Enter the full URL including http:// or https://</div>
          </div>
          
          <div className="mb-4">
            <div className="d-flex justify-content-between align-items-center mb-2">
              <label className="form-label mb-0">Scan Types</label>
              <button
                type="button"
                className="btn btn-sm btn-outline-primary"
                onClick={selectAllScanTypes}
              >
                {allSelected ? 'Deselect All' : 'Select All'} ({selectedCount}/{totalCount})
              </button>
            </div>
            
            {/* Group checkboxes by category */}
            {Object.entries(scanTypesByCategory).map(([category, types]) => (
              <div key={category} className="mb-3">
                <div className="d-flex justify-content-between align-items-center">
                  <h6 className="text-muted mb-2 ms-1">{category}</h6>
                  <button
                    type="button"
                    className="btn btn-sm btn-link p-0 text-decoration-none text-muted"
                    onClick={() => selectCategoryTypes(category)}
                  >
                    {types.every(type => scanTypes[type.id]) ? 'Deselect All' : 'Select All'}
                  </button>
                </div>
                
                <div className="row">
                  {types.map(scanType => (
                    <div className="col-md-6 mb-2" key={scanType.id}>
                      <div className="form-check">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          id={scanType.id}
                          name={scanType.id}
                          checked={scanTypes[scanType.id] || false}
                          onChange={handleCheckboxChange}
                        />
                        <label className="form-check-label d-flex flex-column" htmlFor={scanType.id}>
                          <span>
                            <span className="me-1">{scanType.icon}</span>
                            {scanType.name}
                          </span>
                          <small className="text-muted">{scanType.description}</small>
                        </label>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          
          <button
            type="submit"
            className="btn btn-primary w-100"
            disabled={loading}
          >
            {loading ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                Starting Scan...
              </>
            ) : (
              'Start Scan'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ScanForm;