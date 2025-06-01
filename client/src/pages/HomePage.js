// frontend/src/pages/HomePage.js

import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

const HomePage = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div>
      {/* Hero section */}
      <div className="bg-primary text-white py-5">
        <div className="container py-5">
          <div className="row align-items-center">
            <div className="col-lg-6">
              <h1 className="display-4 fw-bold mb-4">
                Secure Your Website with Comprehensive Analysis
              </h1>
              <p className="lead mb-4">
                Site-Analyser helps you identify security vulnerabilities,
                analyze SSL/TLS configurations, and improve your website's
                security posture with AI-powered recommendations.
              </p>
              {isAuthenticated ? (
                <Link to="/scans/new" className="btn btn-light btn-lg">
                  Start a New Scan
                </Link>
              ) : (
                <Link to="/register" className="btn btn-light btn-lg">
                  Get Started for Free
                </Link>
              )}
            </div>
            <div className="col-lg-6 d-none d-lg-block">
              <img
                alt="Security scanning illustration"
                className="img-fluid w-50"
                src="/assets/images/hero.svg"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Features section */}
      <div className="py-5">
        <div className="container">
          <h2 className="text-center mb-5">Comprehensive Security Analysis</h2>

          <div className="row g-4">
            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <img
                  src="/assets/images/ssl_analysis_icon.svg"
                  alt="SSL/TLS Analysis"
                  className="card-img-top p-4"
                />
                <div className="card-body text-center p-4">
                  <h5 className="card-title">SSL/TLS Analysis</h5>
                  <p className="card-text">
                    Verify your SSL/TLS configuration, detect vulnerabilities,
                    and ensure secure connection between your visitors and
                    website.
                  </p>
                </div>
              </div>
            </div>

            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <img
                  src="/assets/images/header_security_icon.svg"
                  alt="Header Security"
                  className="card-img-top p-4"
                />
                <div className="card-body text-center p-4">
                  <h5 className="card-title">Header Security</h5>
                  <p className="card-text">
                    Analyze HTTP headers for proper security configurations,
                    including Content-Security-Policy, X-Frame-Options, and
                    more.
                  </p>
                </div>
              </div>
            </div>

            <div className="col-md-4">
              <div className="card h-100 border-0 shadow-sm">
                <img
                  src="/assets/images/ai_analysis_icon.svg"
                  alt="AI-Powered Analysis"
                  className="card-img-top p-4"
                />
                <div className="card-body text-center p-4">
                  <h5 className="card-title">AI-Powered Analysis</h5>
                  <p className="card-text">
                    Get intelligent recommendations and security insights
                    powered by our advanced machine learning algorithms.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CTA section */}
      <div className="bg-light py-5">
        <div className="container py-5">
          <div className="row justify-content-center align-items-center">
            <div className="col-lg-6 text-center">
              <h2 className="mb-4">Ready to secure your website?</h2>
              <p className="lead mb-4">
                Start scanning your website today and receive detailed security
                reports and recommendations.
              </p>
              {isAuthenticated ? (
                <Link to="/scans/new" className="btn btn-primary btn-lg">
                  Start a New Scan
                </Link>
              ) : (
                <Link to="/register" className="btn btn-primary btn-lg">
                  Create a Free Account
                </Link>
              )}
            </div>
            <div className="col-lg-6 d-none d-lg-block">
              <img
                alt="Secure your website CTA"
                className="img-fluid"
                src="/assets/images/secure_now_cta.svg"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HomePage;
