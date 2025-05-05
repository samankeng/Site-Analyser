// frontend/src/components/common/Footer.js

import React from 'react';
import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="bg-light text-center text-lg-start mt-auto">
      <div className="container p-4">
        <div className="row">
          <div className="col-lg-6 col-md-12 mb-4 mb-md-0">
            <h5>Site-Analyser</h5>
            <p>
              A comprehensive security scanning tool for websites.
              Identify vulnerabilities, analyze SSL/TLS configurations,
              and improve your website's security posture.
            </p>
          </div>
          
          <div className="col-lg-3 col-md-6 mb-4 mb-md-0">
            <h5>Links</h5>
            <ul className="list-unstyled mb-0">
              <li>
                <Link to="/" className="text-dark">
                  Home
                </Link>
              </li>
              <li>
                <Link to="/dashboard" className="text-dark">
                  Dashboard
                </Link>
              </li>
              <li>
                <Link to="/scans/new" className="text-dark">
                  New Scan
                </Link>
              </li>
              <li>
                <Link to="/reports" className="text-dark">
                  Reports
                </Link>
              </li>
            </ul>
          </div>
          
          <div className="col-lg-3 col-md-6 mb-4 mb-md-0">
            <h5>Resources</h5>
            <ul className="list-unstyled">
              <li>
                <a href="#" className="text-dark">
                  Documentation
                </a>
              </li>
              <li>
                <a href="#" className="text-dark">
                  API Reference
                </a>
              </li>
              <li>
                <a href="#" className="text-dark">
                  Privacy Policy
                </a>
              </li>
              <li>
                <a href="#" className="text-dark">
                  Terms of Service
                </a>
              </li>
            </ul>
          </div>
        </div>
      </div>
      
      <div className="text-center p-3" style={{ backgroundColor: 'rgba(0, 0, 0, 0.05)' }}>
        © {new Date().getFullYear()} Site-Analyser. All rights reserved.
      </div>
    </footer>
  );
};

export default Footer;