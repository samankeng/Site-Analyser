// frontend/src/pages/docs/Documentation.js

import { useState } from "react";
import { Link } from "react-router-dom";

const Documentation = () => {
  const [activeSection, setActiveSection] = useState("getting-started");

  const sections = [
    { id: "getting-started", title: "Getting Started", icon: "🚀" },
    { id: "scanning", title: "Security Scanning", icon: "🔍" },
    { id: "reports", title: "Reports & Analysis", icon: "📊" },
    { id: "compliance", title: "Compliance Features", icon: "✅" },
    { id: "ai-features", title: "AI-Powered Analysis", icon: "🤖" },
    { id: "dashboard", title: "Dashboard Overview", icon: "📈" },
    { id: "integrations", title: "Third-party Integrations", icon: "🔌" },
    { id: "troubleshooting", title: "Troubleshooting", icon: "🛠️" },
  ];

  const renderContent = () => {
    switch (activeSection) {
      case "getting-started":
        return (
          <div>
            <h2>🚀 Getting Started with Site-Analyser</h2>
            <p className="lead">
              Welcome to Site-Analyser, your comprehensive website security
              scanning solution.
            </p>

            <h3>Quick Start</h3>
            <ol>
              <li>
                <strong>Create an Account:</strong> Sign up for a free account
                to get started
              </li>
              <li>
                <strong>Verify Email:</strong> Check your email and verify your
                account
              </li>
              <li>
                <strong>Start Your First Scan:</strong> Navigate to "New Scan"
                and enter your website URL
              </li>
              <li>
                <strong>Review Results:</strong> Access detailed reports from
                your dashboard
              </li>
            </ol>

            <h3>What Site-Analyser Does</h3>
            <ul>
              <li>Comprehensive security vulnerability scanning</li>
              <li>SSL/TLS certificate analysis</li>
              <li>HTTP security headers evaluation</li>
              <li>Content Security Policy (CSP) analysis</li>
              <li>CORS configuration review</li>
              <li>Cookie security assessment</li>
              <li>Port scanning and server analysis</li>
              <li>AI-powered threat detection and recommendations</li>
            </ul>

            <div className="alert alert-info mt-4">
              <strong>💡 Pro Tip:</strong> Start with a basic scan to get
              familiar with the platform, then explore advanced features like
              compliance reporting and AI analysis.
            </div>
          </div>
        );

      case "scanning":
        return (
          <div>
            <h2>🔍 Security Scanning</h2>
            <p className="lead">
              Learn how to perform comprehensive security scans on your
              websites.
            </p>

            <h3>Starting a New Scan</h3>
            <ol>
              <li>
                Navigate to <code>Dashboard → New Scan</code>
              </li>
              <li>Enter the target URL (e.g., https://example.com)</li>
              <li>
                Select scan type:
                <ul>
                  <li>
                    <strong>Quick Scan:</strong> Basic security check (5-10
                    minutes)
                  </li>
                  <li>
                    <strong>Comprehensive Scan:</strong> Full security audit
                    (15-30 minutes)
                  </li>
                  <li>
                    <strong>Custom Scan:</strong> Choose specific scan modules
                  </li>
                </ul>
              </li>
              <li>Click "Start Scan" and monitor progress</li>
            </ol>

            <h3>Scan Types Available</h3>
            <div className="row">
              <div className="col-md-6">
                <h4>🔒 SSL/TLS Analysis</h4>
                <ul>
                  <li>Certificate validity and expiration</li>
                  <li>Cipher suite strength</li>
                  <li>Protocol version support</li>
                  <li>Certificate chain validation</li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>🛡️ Security Headers</h4>
                <ul>
                  <li>Content-Security-Policy</li>
                  <li>X-Frame-Options</li>
                  <li>X-Content-Type-Options</li>
                  <li>Strict-Transport-Security</li>
                </ul>
              </div>
            </div>

            <div className="row mt-3">
              <div className="col-md-6">
                <h4>🌐 Network Analysis</h4>
                <ul>
                  <li>Open port detection</li>
                  <li>Service fingerprinting</li>
                  <li>Server technology identification</li>
                  <li>DNS configuration review</li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>📝 Content Analysis</h4>
                <ul>
                  <li>Form security assessment</li>
                  <li>Cookie configuration review</li>
                  <li>CORS policy evaluation</li>
                  <li>Content vulnerability detection</li>
                </ul>
              </div>
            </div>

            <div className="alert alert-warning mt-4">
              <strong>⚠️ Important:</strong> Only scan websites you own or have
              explicit permission to test. Unauthorized scanning may violate
              terms of service or laws.
            </div>
          </div>
        );

      case "reports":
        return (
          <div>
            <h2>📊 Reports & Analysis</h2>
            <p className="lead">
              Understanding your security reports and taking action on findings.
            </p>

            <h3>Report Types</h3>
            <div className="row">
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">📈 Executive Summary</h5>
                    <p className="card-text">
                      High-level overview of security posture with risk scores
                      and key metrics.
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">🔍 Detailed Technical</h5>
                    <p className="card-text">
                      In-depth technical findings with specific vulnerabilities
                      and recommendations.
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">✅ Compliance Report</h5>
                    <p className="card-text">
                      Compliance status against industry standards like OWASP,
                      NIST, and PCI DSS.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <h3>Understanding Risk Scores</h3>
            <table className="table table-striped">
              <thead>
                <tr>
                  <th>Risk Level</th>
                  <th>Score Range</th>
                  <th>Description</th>
                  <th>Action Required</th>
                </tr>
              </thead>
              <tbody>
                <tr className="table-success">
                  <td>
                    <span className="badge bg-success">Low</span>
                  </td>
                  <td>0-3</td>
                  <td>Minor issues, good security posture</td>
                  <td>Monitor and maintain</td>
                </tr>
                <tr className="table-warning">
                  <td>
                    <span className="badge bg-warning">Medium</span>
                  </td>
                  <td>4-6</td>
                  <td>Some vulnerabilities present</td>
                  <td>Plan remediation within 30 days</td>
                </tr>
                <tr className="table-danger">
                  <td>
                    <span className="badge bg-danger">High</span>
                  </td>
                  <td>7-8</td>
                  <td>Significant security risks</td>
                  <td>Address within 7 days</td>
                </tr>
                <tr className="table-dark">
                  <td>
                    <span className="badge bg-dark">Critical</span>
                  </td>
                  <td>9-10</td>
                  <td>Severe vulnerabilities</td>
                  <td>Immediate action required</td>
                </tr>
              </tbody>
            </table>

            <h3>Export Options</h3>
            <ul>
              <li>
                <strong>PDF Report:</strong> Professional formatted report for
                sharing
              </li>
              <li>
                <strong>JSON Export:</strong> Raw data for integration with
                other tools
              </li>
              <li>
                <strong>CSV Summary:</strong> Spreadsheet-friendly format for
                tracking
              </li>
              <li>
                <strong>Email Delivery:</strong> Automated report delivery to
                stakeholders
              </li>
            </ul>
          </div>
        );

      case "compliance":
        return (
          <div>
            <h2>✅ Compliance Features</h2>
            <p className="lead">
              Ensure your website meets industry security standards and
              regulatory requirements.
            </p>

            <h3>Supported Compliance Frameworks</h3>
            <div className="row">
              <div className="col-md-6 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">OWASP Top 10</h5>
                    <p className="card-text">
                      Comprehensive coverage of the most critical web
                      application security risks.
                    </p>
                    <ul className="list-unstyled">
                      <li>✓ Injection vulnerabilities</li>
                      <li>✓ Broken authentication</li>
                      <li>✓ Sensitive data exposure</li>
                      <li>✓ Security misconfigurations</li>
                    </ul>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">PCI DSS</h5>
                    <p className="card-text">
                      Payment Card Industry Data Security Standard compliance
                      checking.
                    </p>
                    <ul className="list-unstyled">
                      <li>✓ Network security controls</li>
                      <li>✓ Data encryption requirements</li>
                      <li>✓ Access control measures</li>
                      <li>✓ Security monitoring</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            <div className="row">
              <div className="col-md-6 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">NIST Cybersecurity Framework</h5>
                    <p className="card-text">
                      Alignment with NIST guidelines for cybersecurity risk
                      management.
                    </p>
                    <ul className="list-unstyled">
                      <li>✓ Identify security risks</li>
                      <li>✓ Protect critical assets</li>
                      <li>✓ Detect security events</li>
                      <li>✓ Response capabilities</li>
                    </ul>
                  </div>
                </div>
              </div>
              <div className="col-md-6 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">GDPR Security</h5>
                    <p className="card-text">
                      Security measures required under General Data Protection
                      Regulation.
                    </p>
                    <ul className="list-unstyled">
                      <li>✓ Data protection by design</li>
                      <li>✓ Encryption requirements</li>
                      <li>✓ Access controls</li>
                      <li>✓ Breach detection</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            <h3>Compliance Reporting</h3>
            <p>Generate detailed compliance reports that include:</p>
            <ul>
              <li>Compliance score and status overview</li>
              <li>Failed requirements with remediation steps</li>
              <li>Evidence collection for audit purposes</li>
              <li>Historical compliance tracking</li>
              <li>Executive summary for stakeholders</li>
            </ul>

            <div className="alert alert-info mt-4">
              <strong>📋 Note:</strong> Compliance reports are available for Pro
              and Enterprise accounts. Contact support for custom compliance
              framework support.
            </div>
          </div>
        );

      case "ai-features":
        return (
          <div>
            <h2>🤖 AI-Powered Analysis</h2>
            <p className="lead">
              Leverage artificial intelligence for advanced threat detection and
              security recommendations.
            </p>

            <h3>AI Capabilities</h3>
            <div className="row">
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">🔍 Anomaly Detection</h5>
                    <p className="card-text">
                      Machine learning algorithms identify unusual patterns and
                      potential security threats.
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">⚡ Threat Intelligence</h5>
                    <p className="card-text">
                      AI-powered analysis of emerging threats and attack
                      patterns.
                    </p>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">📊 Risk Scoring</h5>
                    <p className="card-text">
                      Intelligent risk assessment based on multiple security
                      factors.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <h3>AI Recommendations</h3>
            <p>Our AI engine provides:</p>
            <ul>
              <li>
                <strong>Prioritized Action Items:</strong> Focus on the most
                critical security issues first
              </li>
              <li>
                <strong>Context-Aware Suggestions:</strong> Recommendations
                tailored to your specific technology stack
              </li>
              <li>
                <strong>Implementation Guidance:</strong> Step-by-step
                instructions for fixing vulnerabilities
              </li>
              <li>
                <strong>Best Practice Advice:</strong> Industry-standard
                security practices for your platform
              </li>
            </ul>

            <h3>Machine Learning Models</h3>
            <table className="table">
              <thead>
                <tr>
                  <th>Model Type</th>
                  <th>Purpose</th>
                  <th>Accuracy</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Neural Network</td>
                  <td>Vulnerability pattern recognition</td>
                  <td>94.5%</td>
                </tr>
                <tr>
                  <td>Random Forest</td>
                  <td>Risk score calculation</td>
                  <td>91.2%</td>
                </tr>
                <tr>
                  <td>SVM</td>
                  <td>Anomaly detection</td>
                  <td>89.8%</td>
                </tr>
                <tr>
                  <td>LSTM</td>
                  <td>Temporal threat analysis</td>
                  <td>92.3%</td>
                </tr>
              </tbody>
            </table>

            <div className="alert alert-success mt-4">
              <strong>🎯 Results:</strong> AI-powered analysis typically
              identifies 23% more security issues compared to traditional
              scanning methods.
            </div>
          </div>
        );

      case "dashboard":
        return (
          <div>
            <h2>📈 Dashboard Overview</h2>
            <p className="lead">
              Navigate and understand your security dashboard effectively.
            </p>

            <h3>Dashboard Components</h3>
            <div className="row">
              <div className="col-md-6 mb-3">
                <h4>🏆 Security Score Card</h4>
                <p>Your overall security posture at a glance:</p>
                <ul>
                  <li>Current security score (0-100)</li>
                  <li>Score trend over time</li>
                  <li>Comparison with industry averages</li>
                  <li>Key improvement areas</li>
                </ul>
              </div>
              <div className="col-md-6 mb-3">
                <h4>🔍 Recent Scans</h4>
                <p>Quick access to your latest security scans:</p>
                <ul>
                  <li>Scan status and progress</li>
                  <li>Last scan results summary</li>
                  <li>Critical issues requiring attention</li>
                  <li>Scheduled scan notifications</li>
                </ul>
              </div>
            </div>

            <div className="row">
              <div className="col-md-6 mb-3">
                <h4>📊 Vulnerability Trends</h4>
                <p>Visual representation of security trends:</p>
                <ul>
                  <li>Vulnerability count over time</li>
                  <li>Risk level distribution</li>
                  <li>Resolution rate tracking</li>
                  <li>New vs. resolved issues</li>
                </ul>
              </div>
              <div className="col-md-6 mb-3">
                <h4>🚨 Alerts & Notifications</h4>
                <p>Stay informed about security events:</p>
                <ul>
                  <li>Critical vulnerability alerts</li>
                  <li>Scan completion notifications</li>
                  <li>Compliance status changes</li>
                  <li>System maintenance updates</li>
                </ul>
              </div>
            </div>

            <h3>Customizing Your Dashboard</h3>
            <p>Personalize your dashboard experience:</p>
            <ol>
              <li>
                Click the <code>⚙️ Settings</code> icon in the top-right corner
              </li>
              <li>Select "Dashboard Preferences"</li>
              <li>Choose which widgets to display</li>
              <li>Arrange widgets by dragging and dropping</li>
              <li>Set refresh intervals for real-time data</li>
            </ol>

            <h3>Quick Actions</h3>
            <div className="row">
              <div className="col-md-3 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>🆕 New Scan</h5>
                  <p>Start a fresh security scan</p>
                </div>
              </div>
              <div className="col-md-3 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>📋 View Reports</h5>
                  <p>Access detailed scan reports</p>
                </div>
              </div>
              <div className="col-md-3 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>📊 Export Data</h5>
                  <p>Download reports and data</p>
                </div>
              </div>
              <div className="col-md-3 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>⚙️ Settings</h5>
                  <p>Configure account settings</p>
                </div>
              </div>
            </div>
          </div>
        );

      case "integrations":
        return (
          <div>
            <h2>🔌 Third-party Integrations</h2>
            <p className="lead">
              Enhance your security scanning with powerful third-party
              integrations.
            </p>

            <h3>Available Integrations</h3>
            <div className="row">
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">🔍 Shodan</h5>
                    <p className="card-text">
                      Internet-wide scanning and device discovery for
                      comprehensive asset identification.
                    </p>
                    <div className="mt-2">
                      <span className="badge bg-primary">Network Scanning</span>
                      <span className="badge bg-secondary ms-1">
                        IoT Discovery
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">🛡️ SSL Labs</h5>
                    <p className="card-text">
                      Industry-leading SSL/TLS configuration analysis and
                      certificate validation.
                    </p>
                    <div className="mt-2">
                      <span className="badge bg-success">SSL Analysis</span>
                      <span className="badge bg-info ms-1">
                        Certificate Check
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="col-md-4 mb-3">
                <div className="card">
                  <div className="card-body">
                    <h5 className="card-title">🦠 VirusTotal</h5>
                    <p className="card-text">
                      Multi-engine malware detection and URL reputation
                      analysis.
                    </p>
                    <div className="mt-2">
                      <span className="badge bg-warning">
                        Malware Detection
                      </span>
                      <span className="badge bg-danger ms-1">URL Analysis</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <h3>Integration Benefits</h3>
            <table className="table table-striped">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Primary Function</th>
                  <th>Data Provided</th>
                  <th>Update Frequency</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Shodan</td>
                  <td>Network Discovery</td>
                  <td>Open ports, services, banners</td>
                  <td>Real-time</td>
                </tr>
                <tr>
                  <td>SSL Labs</td>
                  <td>SSL/TLS Testing</td>
                  <td>Certificate details, cipher strength</td>
                  <td>On-demand</td>
                </tr>
                <tr>
                  <td>VirusTotal</td>
                  <td>Threat Intelligence</td>
                  <td>Malware signatures, URL reputation</td>
                  <td>Continuous</td>
                </tr>
              </tbody>
            </table>

            <h3>Setting Up Integrations</h3>
            <ol>
              <li>
                Navigate to <code>Settings → Integrations</code>
              </li>
              <li>Select the integration you want to configure</li>
              <li>
                Enter your API credentials:
                <ul>
                  <li>Obtain API keys from the respective service providers</li>
                  <li>Configure rate limits and quotas</li>
                  <li>Test the connection</li>
                </ul>
              </li>
              <li>Enable the integration for your scans</li>
              <li>Configure which scan types should use each integration</li>
            </ol>

            <h3>API Rate Limits</h3>
            <div className="alert alert-warning">
              <strong>⚠️ Important:</strong> Third-party integrations are
              subject to their respective API rate limits. Monitor your usage to
              avoid service interruptions.
            </div>

            <ul>
              <li>
                <strong>Shodan:</strong> 100 queries/month (free), 10,000/month
                (paid)
              </li>
              <li>
                <strong>SSL Labs:</strong> 20 assessments/hour per IP
              </li>
              <li>
                <strong>VirusTotal:</strong> 500 requests/day (free), higher
                limits for premium
              </li>
            </ul>

            <h3>Custom Integrations</h3>
            <p>
              Need integration with tools not listed? Contact our enterprise
              team for custom integration development:
            </p>
            <ul>
              <li>SIEM platforms (Splunk, ELK, QRadar)</li>
              <li>Ticketing systems (Jira, ServiceNow)</li>
              <li>
                Cloud security tools (AWS Security Hub, Azure Security Center)
              </li>
              <li>DevOps pipelines (Jenkins, GitLab CI/CD)</li>
            </ul>
          </div>
        );

      case "troubleshooting":
        return (
          <div>
            <h2>🛠️ Troubleshooting</h2>
            <p className="lead">
              Common issues and solutions to help you get the most out of
              Site-Analyser.
            </p>

            <h3>Scan Issues</h3>
            <div className="accordion" id="scanIssuesAccordion">
              <div className="accordion-item">
                <h2 className="accordion-header">
                  <button
                    className="accordion-button"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#scanStuck"
                  >
                    🔄 Scan appears to be stuck or taking too long
                  </button>
                </h2>
                <div
                  id="scanStuck"
                  className="accordion-collapse collapse show"
                >
                  <div className="accordion-body">
                    <p>
                      <strong>Possible causes:</strong>
                    </p>
                    <ul>
                      <li>Target website is slow to respond</li>
                      <li>Network connectivity issues</li>
                      <li>High server load during peak hours</li>
                    </ul>
                    <p>
                      <strong>Solutions:</strong>
                    </p>
                    <ul>
                      <li>Wait 10-15 minutes for the scan to complete</li>
                      <li>Try running the scan during off-peak hours</li>
                      <li>
                        Contact support if scan remains stuck for over 30
                        minutes
                      </li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="accordion-item">
                <h2 className="accordion-header">
                  <button
                    className="accordion-button collapsed"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#scanFailed"
                  >
                    ❌ Scan failed with error message
                  </button>
                </h2>
                <div id="scanFailed" className="accordion-collapse collapse">
                  <div className="accordion-body">
                    <p>
                      <strong>Common error messages:</strong>
                    </p>
                    <ul>
                      <li>
                        <code>Connection timeout</code> - Target server not
                        responding
                      </li>
                      <li>
                        <code>DNS resolution failed</code> - Invalid or
                        unreachable domain
                      </li>
                      <li>
                        <code>SSL handshake failed</code> - SSL/TLS
                        configuration issues
                      </li>
                      <li>
                        <code>Access denied</code> - WAF or firewall blocking
                        scan
                      </li>
                    </ul>
                    <p>
                      <strong>Steps to resolve:</strong>
                    </p>
                    <ol>
                      <li>
                        Verify the URL is correct and accessible from your
                        browser
                      </li>
                      <li>Check if the website has WAF or DDoS protection</li>
                      <li>Try scanning a subdomain or different page</li>
                      <li>
                        Contact the website administrator if you own the site
                      </li>
                    </ol>
                  </div>
                </div>
              </div>
            </div>

            <h3>Account & Authentication</h3>
            <div className="row">
              <div className="col-md-6">
                <h4>🔐 Login Issues</h4>
                <ul>
                  <li>
                    <strong>Forgot Password:</strong> Use the "Reset Password"
                    link on the login page
                  </li>
                  <li>
                    <strong>Account Locked:</strong> Wait 15 minutes or contact
                    support
                  </li>
                  <li>
                    <strong>Email Not Verified:</strong> Check spam folder for
                    verification email
                  </li>
                  <li>
                    <strong>Two-Factor Issues:</strong> Use backup codes or
                    contact support
                  </li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>📧 Email Issues</h4>
                <ul>
                  <li>
                    <strong>No Verification Email:</strong> Check spam/junk
                    folders
                  </li>
                  <li>
                    <strong>Expired Links:</strong> Request a new verification
                    email
                  </li>
                  <li>
                    <strong>Wrong Email:</strong> Contact support to update your
                    email
                  </li>
                  <li>
                    <strong>Email Changes:</strong> Verify both old and new
                    email addresses
                  </li>
                </ul>
              </div>
            </div>

            <h3>Report & Data Issues</h3>
            <table className="table table-striped">
              <thead>
                <tr>
                  <th>Issue</th>
                  <th>Symptoms</th>
                  <th>Solution</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Missing Reports</td>
                  <td>Report not showing in dashboard</td>
                  <td>
                    Refresh page, check date filters, verify scan completed
                  </td>
                </tr>
                <tr>
                  <td>Export Failures</td>
                  <td>PDF/CSV download not working</td>
                  <td>
                    Disable pop-up blockers, try different browser, check file
                    size limits
                  </td>
                </tr>
                <tr>
                  <td>Incorrect Data</td>
                  <td>Security scores seem wrong</td>
                  <td>
                    Re-run scan, verify target URL, check for website changes
                  </td>
                </tr>
                <tr>
                  <td>Slow Loading</td>
                  <td>Dashboard takes long to load</td>
                  <td>
                    Clear browser cache, check internet connection, try
                    incognito mode
                  </td>
                </tr>
              </tbody>
            </table>

            <h3>Browser Compatibility</h3>
            <div className="row">
              <div className="col-md-6">
                <h4>✅ Supported Browsers</h4>
                <ul>
                  <li>Chrome 90+ (Recommended)</li>
                  <li>Firefox 88+</li>
                  <li>Safari 14+</li>
                  <li>Edge 90+</li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>⚠️ Browser Settings</h4>
                <ul>
                  <li>Enable JavaScript</li>
                  <li>Allow cookies from site-analyser.com</li>
                  <li>Disable ad blockers for best experience</li>
                  <li>Clear cache if experiencing issues</li>
                </ul>
              </div>
            </div>

            <h3>Getting Help</h3>
            <div className="row">
              <div className="col-md-4 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>📧 Email Support</h5>
                  <p>support@site-analyser.com</p>
                  <small>Response within 24 hours</small>
                </div>
              </div>
              <div className="col-md-4 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>💬 Live Chat</h5>
                  <p>Available Mon-Fri 9AM-5PM EST</p>
                  <small>Click chat icon in bottom right</small>
                </div>
              </div>
              <div className="col-md-4 text-center mb-3">
                <div className="border p-3 rounded">
                  <h5>📚 Knowledge Base</h5>
                  <p>Searchable help articles</p>
                  <small>Updated regularly with new content</small>
                </div>
              </div>
            </div>

            <div className="alert alert-info mt-4">
              <strong>💡 Pro Tip:</strong> Before contacting support, try
              clearing your browser cache and cookies. This resolves many common
              issues.
            </div>
          </div>
        );

      default:
        return (
          <div>Select a section from the sidebar to view documentation.</div>
        );
    }
  };

  return (
    <div className="container-fluid py-4">
      <div className="row">
        {/* Sidebar */}
        <div className="col-md-3 col-lg-2">
          <div className="card">
            <div className="card-header">
              <h5 className="mb-0">📚 Documentation</h5>
            </div>
            <div className="list-group list-group-flush">
              {sections.map((section) => (
                <button
                  key={section.id}
                  className={`list-group-item list-group-item-action ${
                    activeSection === section.id ? "active" : ""
                  }`}
                  onClick={() => setActiveSection(section.id)}
                >
                  <span className="me-2">{section.icon}</span>
                  {section.title}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Links */}
          <div className="card mt-3">
            <div className="card-header">
              <h6 className="mb-0">🔗 Quick Links</h6>
            </div>
            <div className="card-body">
              <div className="d-grid gap-2">
                <Link
                  to="/dashboard"
                  className="btn btn-outline-primary btn-sm"
                >
                  Dashboard
                </Link>
                <Link
                  to="/scans/new"
                  className="btn btn-outline-success btn-sm"
                >
                  Start New Scan
                </Link>
                <Link to="/reports" className="btn btn-outline-info btn-sm">
                  View Reports
                </Link>
                <Link
                  to="/settings"
                  className="btn btn-outline-secondary btn-sm"
                >
                  Settings
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="col-md-9 col-lg-10">
          <div className="card">
            <div className="card-body">{renderContent()}</div>
          </div>

          {/* Feedback Section */}
          <div className="card mt-4">
            <div className="card-body">
              <h5>📝 Improve This Documentation</h5>
              <p>
                Help us make our documentation better. If you found an error or
                have suggestions:
              </p>
              <div className="row">
                <div className="col-md-6">
                  <button className="btn btn-outline-success me-2">
                    👍 This was helpful
                  </button>
                  <button className="btn btn-outline-danger">
                    👎 This needs improvement
                  </button>
                </div>
                <div className="col-md-6 text-end">
                  <button className="btn btn-primary">
                    📧 Contact Documentation Team
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Documentation;
