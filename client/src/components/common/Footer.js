// frontend/src/components/common/Footer.js

import { Link } from "react-router-dom";

const Footer = () => {
  // Handlers for external links or actions
  const handleDocumentationClick = () => {
    // Navigate to documentation page or external docs
    window.open("/docs", "_blank");
  };

  const handleApiReferenceClick = () => {
    // Navigate to API documentation
    window.open("/api-reference", "_blank");
  };

  const handlePrivacyClick = () => {
    // Navigate to privacy policy page
    window.location.href = "/privacy-policy";
  };

  const handleTermsClick = () => {
    // Navigate to terms of service page
    window.location.href = "/terms-of-service";
  };

  return (
    <footer className="bg-light text-center text-lg-start mt-auto">
      <div className="container p-4">
        <div className="row">
          <div className="col-lg-6 col-md-12 mb-4 mb-md-0">
            <h5>Site-Analyser</h5>
            <p>
              A comprehensive security scanning tool for websites. Identify
              vulnerabilities, analyze SSL/TLS configurations, and improve your
              website's security posture.
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
                <button
                  type="button"
                  className="btn btn-link text-dark p-0 text-start"
                  onClick={handleDocumentationClick}
                >
                  Documentation
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className="btn btn-link text-dark p-0 text-start"
                  onClick={handleApiReferenceClick}
                >
                  API Reference
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className="btn btn-link text-dark p-0 text-start"
                  onClick={handlePrivacyClick}
                >
                  Privacy Policy
                </button>
              </li>
              <li>
                <button
                  type="button"
                  className="btn btn-link text-dark p-0 text-start"
                  onClick={handleTermsClick}
                >
                  Terms of Service
                </button>
              </li>
            </ul>
          </div>
        </div>
      </div>

      <div
        className="text-center p-3"
        style={{ backgroundColor: "rgba(0, 0, 0, 0.05)" }}
      >
        © {new Date().getFullYear()} Site-Analyser. All rights reserved.
      </div>
    </footer>
  );
};

export default Footer;
