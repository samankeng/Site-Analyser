// frontend/src/pages/scans/NewScan.js

import React from 'react';
import { Link } from 'react-router-dom';
import ScanForm from '../../components/security/ScanForm';

const NewScan = () => {
  return (
    <div className="container py-4">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>New Security Scan</h2>
        <Link to="/dashboard" className="btn btn-outline-secondary">
          Back to Dashboard
        </Link>
      </div>
      
      <div className="row">
        <div className="col-lg-8">
          <ScanForm />
        </div>
        
        <div className="col-lg-4">
          <div className="card shadow-sm">
            <div className="card-body">
              <h5 className="card-title">Scan Types</h5>
              
              <div className="mt-3">
                <h6>HTTP Headers Analysis</h6>
                <p className="text-muted small">
                  Examines HTTP headers for missing security headers such as Content-Security-Policy,
                  X-Frame-Options, and Strict-Transport-Security.
                </p>
              </div>
              
              <div className="mt-3">
                <h6>SSL/TLS Configuration</h6>
                <p className="text-muted small">
                  Checks SSL/TLS certificate validity, protocol versions, and cipher suites to identify
                  potential vulnerabilities.
                </p>
              </div>
              
              <div className="mt-3">
                <h6>Vulnerability Scan</h6>
                <p className="text-muted small">
                  Detects common web vulnerabilities such as exposed sensitive files, outdated software
                  versions, and security misconfigurations.
                </p>
              </div>
              
              <div className="mt-3">
                <h6>Content Analysis</h6>
                <p className="text-muted small">
                  Analyzes page content for SEO issues, accessibility problems, and potential information
                  disclosure risks.
                </p>
              </div>
              
              <div className="mt-3">
                <h6>Port Scanning</h6>
                <p className="text-muted small">
                  Identifies open ports and services that could potentially expose your infrastructure
                  to attackers.
                </p>
              </div>
              
              <div className="mt-3">
                <h6>Content Security Policy</h6>
                <p className="text-muted small">
                  Evaluates your CSP implementation to ensure proper protection against cross-site scripting
                  (XSS) and other code injection attacks.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NewScan;