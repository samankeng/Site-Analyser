// frontend/src/pages/docs/TermsOfService.js

import { useEffect } from "react";
import { Link } from "react-router-dom";

const TermsOfService = () => {
  // Smooth scroll to sections when clicking table of contents
  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
  };

  // Add scroll padding to account for any fixed headers
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = `
      html {
        scroll-padding-top: 20px;
      }
      .table-responsive {
        overflow-x: auto;
      }
    `;
    document.head.appendChild(style);

    return () => {
      document.head.removeChild(style);
    };
  }, []);

  return (
    <div className="container py-5">
      <div className="row justify-content-center">
        <div className="col-lg-10 col-xl-8">
          <div className="card shadow">
            <div className="card-body p-4 p-md-5">
              {/* Header */}
              <div className="text-center mb-5">
                <h1 className="display-5 fw-bold text-primary">
                  Terms of Service
                </h1>
                <p className="lead text-muted">
                  These Terms of Service govern your use of Site-Analyser's
                  security scanning platform and services.
                </p>
                <hr className="my-4" />
                <div className="row text-start">
                  <div className="col-md-6">
                    <small className="text-muted">
                      <strong>Effective Date:</strong> June 1, 2025
                    </small>
                  </div>
                  <div className="col-md-6">
                    <small className="text-muted">
                      <strong>Last Updated:</strong> June 1, 2025
                    </small>
                  </div>
                </div>
              </div>

              {/* Table of Contents */}
              <div className="mb-5">
                <h3>📋 Table of Contents</h3>
                <div className="list-group list-group-flush">
                  <button
                    onClick={() => scrollToSection("acceptance")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    1. Acceptance of Terms
                  </button>
                  <button
                    onClick={() => scrollToSection("description")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    2. Description of Service
                  </button>
                  <button
                    onClick={() => scrollToSection("account-registration")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    3. Account Registration and Security
                  </button>
                  <button
                    onClick={() => scrollToSection("acceptable-use")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    4. Acceptable Use Policy
                  </button>
                  <button
                    onClick={() => scrollToSection("scanning-guidelines")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    5. Scanning Guidelines and Restrictions
                  </button>
                  <button
                    onClick={() => scrollToSection("subscription-billing")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    6. Subscription and Billing
                  </button>
                  <button
                    onClick={() => scrollToSection("intellectual-property")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    7. Intellectual Property Rights
                  </button>
                  <button
                    onClick={() => scrollToSection("data-ownership")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    8. Data Ownership and Usage
                  </button>
                  <button
                    onClick={() => scrollToSection("disclaimers")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    9. Disclaimers and Limitations
                  </button>
                  <button
                    onClick={() => scrollToSection("indemnification")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    10. Indemnification
                  </button>
                  <button
                    onClick={() => scrollToSection("termination")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    11. Termination
                  </button>
                  <button
                    onClick={() => scrollToSection("governing-law")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    12. Governing Law and Disputes
                  </button>
                  <button
                    onClick={() => scrollToSection("miscellaneous")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    13. Miscellaneous
                  </button>
                  <button
                    onClick={() => scrollToSection("contact-information")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    14. Contact Information
                  </button>
                </div>
              </div>

              {/* Content Sections */}
              <section id="acceptance" className="mb-5">
                <h2 className="h3 text-primary mb-3">1. Acceptance of Terms</h2>

                <p>
                  By accessing or using Site-Analyser's website security
                  scanning platform ("Service"), you agree to be bound by these
                  Terms of Service ("Terms"). If you disagree with any part of
                  these terms, you may not access the Service.
                </p>

                <h4>Agreement Scope</h4>
                <p>
                  These Terms constitute a legally binding agreement between you
                  ("User," "Customer," or "you") and Site-Analyser, Inc.
                  ("Site-Analyser," "we," "us," or "our"). This agreement
                  covers:
                </p>
                <ul>
                  <li>Use of our web application and dashboard</li>
                  <li>API access and integration services</li>
                  <li>Security scanning and analysis tools</li>
                  <li>Reporting and compliance features</li>
                  <li>Customer support and documentation</li>
                </ul>

                <h4>Modifications to Terms</h4>
                <p>
                  We reserve the right to modify these Terms at any time. We
                  will notify users of material changes through:
                </p>
                <ul>
                  <li>Email notification to registered users</li>
                  <li>In-app notifications in your dashboard</li>
                  <li>Notice posted on our website</li>
                </ul>

                <p>
                  Continued use of the Service after notification constitutes
                  acceptance of the modified Terms.
                </p>

                <div className="alert alert-info">
                  <strong>📝 Important:</strong> Please read these Terms
                  carefully and save a copy for your records. If you are using
                  the Service on behalf of an organization, you represent that
                  you have authority to bind that organization to these Terms.
                </div>
              </section>

              <section id="description" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  2. Description of Service
                </h2>

                <p>
                  Site-Analyser provides automated website security scanning and
                  analysis services designed to help organizations identify
                  vulnerabilities, assess security posture, and maintain
                  compliance with industry standards.
                </p>

                <h4>Core Services</h4>
                <ul>
                  <li>
                    <strong>Vulnerability Scanning:</strong> Automated detection
                    of security weaknesses in web applications
                  </li>
                  <li>
                    <strong>SSL/TLS Analysis:</strong> Certificate validation
                    and encryption strength assessment
                  </li>
                  <li>
                    <strong>Compliance Checking:</strong> Assessment against
                    frameworks like OWASP, PCI DSS, and NIST
                  </li>
                  <li>
                    <strong>AI-Powered Analysis:</strong> Machine learning-based
                    threat detection and recommendations
                  </li>
                  <li>
                    <strong>Reporting Tools:</strong> Detailed technical and
                    executive reports
                  </li>
                  <li>
                    <strong>API Access:</strong> Programmatic integration
                    capabilities
                  </li>
                </ul>

                <h4>Service Availability</h4>
                <p>
                  We strive to maintain high service availability, but cannot
                  guarantee uninterrupted access. Planned maintenance will be
                  scheduled during off-peak hours with advance notice.
                </p>

                <h4>Service Limitations</h4>
                <p>
                  Our Service has certain technical and practical limitations:
                </p>
                <ul>
                  <li>
                    Scanning is limited to publicly accessible web resources
                  </li>
                  <li>
                    Some security measures may prevent or limit scanning
                    effectiveness
                  </li>
                  <li>
                    AI analysis accuracy depends on available data and training
                    models
                  </li>
                  <li>
                    Third-party integrations are subject to external service
                    availability
                  </li>
                </ul>

                <h4>Beta Features</h4>
                <p>
                  We may offer beta or experimental features that are clearly
                  marked as such. These features:
                </p>
                <ul>
                  <li>Are provided "as-is" without warranties</li>
                  <li>May be discontinued without notice</li>
                  <li>Should not be used for critical security decisions</li>
                  <li>May have limited or no customer support</li>
                </ul>
              </section>

              <section id="account-registration" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  3. Account Registration and Security
                </h2>

                <h4>Registration Requirements</h4>
                <p>To use our Service, you must:</p>
                <ul>
                  <li>
                    Be at least 18 years old or the age of majority in your
                    jurisdiction
                  </li>
                  <li>
                    Provide accurate, current, and complete registration
                    information
                  </li>
                  <li>Maintain and update your account information</li>
                  <li>Use a valid email address that you control</li>
                  <li>Verify your email address when requested</li>
                </ul>

                <h4>Account Security</h4>
                <p>You are responsible for:</p>
                <ul>
                  <li>
                    <strong>Password Security:</strong> Choosing a strong,
                    unique password
                  </li>
                  <li>
                    <strong>Account Access:</strong> Keeping your login
                    credentials confidential
                  </li>
                  <li>
                    <strong>Two-Factor Authentication:</strong> Enabling 2FA
                    when available
                  </li>
                  <li>
                    <strong>Unauthorized Use:</strong> Monitoring and reporting
                    suspicious account activity
                  </li>
                  <li>
                    <strong>Account Sharing:</strong> Not sharing your account
                    with unauthorized users
                  </li>
                </ul>

                <h4>API Keys and Access Tokens</h4>
                <p>If you use our API services:</p>
                <ul>
                  <li>Treat API keys as confidential information</li>
                  <li>Rotate keys regularly and immediately if compromised</li>
                  <li>Use appropriate access controls and monitoring</li>
                  <li>
                    Do not embed keys in client-side code or public repositories
                  </li>
                </ul>

                <h4>Account Types</h4>
                <div className="table-responsive">
                  <table className="table table-striped">
                    <thead>
                      <tr>
                        <th>Account Type</th>
                        <th>Features</th>
                        <th>Limitations</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Individual</td>
                        <td>Personal use, basic features</td>
                        <td>Single user, limited scans</td>
                      </tr>
                      <tr>
                        <td>Team</td>
                        <td>Multi-user access, collaboration</td>
                        <td>User limits based on plan</td>
                      </tr>
                      <tr>
                        <td>Enterprise</td>
                        <td>Full features, custom integrations</td>
                        <td>Subject to contract terms</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="alert alert-warning">
                  <strong>⚠️ Security Notice:</strong> You must immediately
                  notify us of any unauthorized use of your account or any other
                  breach of security. We are not liable for losses caused by
                  unauthorized use of your account.
                </div>
              </section>

              <section id="acceptable-use" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  4. Acceptable Use Policy
                </h2>

                <h4>Permitted Uses</h4>
                <p>You may use our Service to:</p>
                <ul>
                  <li>Scan websites and web applications you own or operate</li>
                  <li>
                    Scan systems with explicit written permission from the owner
                  </li>
                  <li>
                    Conduct authorized security assessments and penetration
                    testing
                  </li>
                  <li>Perform compliance audits and security research</li>
                  <li>Generate reports for legitimate business purposes</li>
                </ul>

                <h4>Prohibited Uses</h4>
                <p>You may NOT use our Service to:</p>
                <ul>
                  <li>
                    <strong>Unauthorized Scanning:</strong> Scan systems without
                    explicit permission
                  </li>
                  <li>
                    <strong>Malicious Activities:</strong> Conduct attacks,
                    exploits, or harmful activities
                  </li>
                  <li>
                    <strong>Illegal Purposes:</strong> Violate any applicable
                    laws or regulations
                  </li>
                  <li>
                    <strong>Service Abuse:</strong> Overload, disrupt, or
                    interfere with our infrastructure
                  </li>
                  <li>
                    <strong>Competitive Intelligence:</strong> Gather data about
                    competitors without authorization
                  </li>
                  <li>
                    <strong>Data Mining:</strong> Extract or harvest data for
                    unauthorized purposes
                  </li>
                  <li>
                    <strong>Circumvention:</strong> Bypass or attempt to bypass
                    service limitations
                  </li>
                </ul>

                <h4>Scanning Ethics</h4>
                <p>When using our scanning services, you must:</p>
                <ul>
                  <li>
                    Obtain proper authorization before scanning any system
                  </li>
                  <li>Respect robots.txt files and rate limiting</li>
                  <li>
                    Avoid scanning during peak business hours without permission
                  </li>
                  <li>Stop scanning if requested by the system owner</li>
                  <li>
                    Follow responsible disclosure practices for vulnerabilities
                  </li>
                </ul>

                <h4>Content Standards</h4>
                <p>Content you provide through our Service must not:</p>
                <ul>
                  <li>Contain malware, viruses, or malicious code</li>
                  <li>Infringe on intellectual property rights</li>
                  <li>
                    Include personal information of others without consent
                  </li>
                  <li>
                    Violate privacy rights or applicable data protection laws
                  </li>
                  <li>Contain false, misleading, or defamatory information</li>
                </ul>

                <h4>Enforcement</h4>
                <p>Violations of this Acceptable Use Policy may result in:</p>
                <ul>
                  <li>Warning and required corrective action</li>
                  <li>Temporary suspension of service access</li>
                  <li>Permanent account termination</li>
                  <li>Legal action and cooperation with law enforcement</li>
                  <li>Charges for investigation and remediation costs</li>
                </ul>
              </section>

              <section id="scanning-guidelines" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  5. Scanning Guidelines and Restrictions
                </h2>

                <h4>Authorization Requirements</h4>
                <p>Before initiating any scan, you must ensure you have:</p>
                <ul>
                  <li>
                    <strong>Ownership:</strong> Legal ownership or control of
                    the target system
                  </li>
                  <li>
                    <strong>Written Permission:</strong> Explicit authorization
                    from the system owner
                  </li>
                  <li>
                    <strong>Legal Authority:</strong> Proper legal basis for
                    conducting the scan
                  </li>
                  <li>
                    <strong>Compliance Check:</strong> Verification that
                    scanning doesn't violate applicable laws
                  </li>
                </ul>

                <h4>Technical Limitations</h4>
                <p>
                  Our scanning service operates within these technical
                  boundaries:
                </p>
                <ul>
                  <li>
                    <strong>Rate Limiting:</strong> Scans are rate-limited to
                    prevent service disruption
                  </li>
                  <li>
                    <strong>Scope Restrictions:</strong> Limited to
                    web-accessible resources and services
                  </li>
                  <li>
                    <strong>Geographic Limits:</strong> Some regions may be
                    restricted due to legal requirements
                  </li>
                  <li>
                    <strong>Protocol Support:</strong> Limited to supported
                    protocols and technologies
                  </li>
                </ul>

                <h4>Restricted Targets</h4>
                <p>You may not scan:</p>
                <ul>
                  <li>
                    Government or military systems without specific
                    authorization
                  </li>
                  <li>
                    Critical infrastructure (power grids, healthcare systems,
                    etc.)
                  </li>
                  <li>Systems explicitly protected by legal safe harbors</li>
                  <li>Educational institutions without proper authorization</li>
                  <li>Systems where scanning is expressly prohibited</li>
                </ul>

                <h4>Scan Frequency and Volume</h4>
                <p>Scan limits are based on your subscription plan:</p>
                <div className="table-responsive">
                  <table className="table table-striped">
                    <thead>
                      <tr>
                        <th>Plan</th>
                        <th>Monthly Scans</th>
                        <th>Concurrent Scans</th>
                        <th>Scan Depth</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Free</td>
                        <td>10</td>
                        <td>1</td>
                        <td>Limited</td>
                      </tr>
                      <tr>
                        <td>Professional</td>
                        <td>100</td>
                        <td>3</td>
                        <td>Standard</td>
                      </tr>
                      <tr>
                        <td>Enterprise</td>
                        <td>Unlimited</td>
                        <td>10+</td>
                        <td>Full</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <h4>Responsible Disclosure</h4>
                <p>
                  If our scans identify vulnerabilities in systems you're
                  authorized to test:
                </p>
                <ul>
                  <li>Follow responsible disclosure practices</li>
                  <li>
                    Allow reasonable time for remediation before public
                    disclosure
                  </li>
                  <li>
                    Do not exploit vulnerabilities beyond proof-of-concept
                  </li>
                  <li>Coordinate with relevant security teams or contacts</li>
                </ul>

                <div className="alert alert-danger">
                  <strong>🚨 Critical Warning:</strong> Unauthorized scanning
                  can be illegal and may result in criminal charges. Always
                  ensure you have proper authorization before scanning any
                  system you do not own.
                </div>
              </section>

              <section id="subscription-billing" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  6. Subscription and Billing
                </h2>

                <h4>Subscription Plans</h4>
                <p>
                  We offer various subscription plans with different features
                  and usage limits:
                </p>
                <ul>
                  <li>
                    <strong>Free Plan:</strong> Limited features for evaluation
                    and light use
                  </li>
                  <li>
                    <strong>Professional Plans:</strong> Monthly or annual
                    billing with full features
                  </li>
                  <li>
                    <strong>Enterprise Plans:</strong> Custom pricing with
                    additional services
                  </li>
                  <li>
                    <strong>Add-ons:</strong> Additional capacity and
                    specialized features
                  </li>
                </ul>

                <h4>Billing Terms</h4>
                <p>By subscribing to a paid plan, you agree that:</p>
                <ul>
                  <li>
                    <strong>Payment Authorization:</strong> You authorize
                    automatic recurring charges
                  </li>
                  <li>
                    <strong>Billing Cycle:</strong> Charges occur on your
                    specified billing cycle
                  </li>
                  <li>
                    <strong>Price Changes:</strong> We may change prices with 30
                    days notice
                  </li>
                  <li>
                    <strong>Tax Responsibility:</strong> You're responsible for
                    applicable taxes
                  </li>
                  <li>
                    <strong>Currency:</strong> All prices are in USD unless
                    otherwise specified
                  </li>
                </ul>

                <h4>Payment Methods</h4>
                <p>We accept:</p>
                <ul>
                  <li>
                    Major credit cards (Visa, MasterCard, American Express)
                  </li>
                  <li>PayPal for individual accounts</li>
                  <li>Wire transfers for enterprise accounts</li>
                  <li>Purchase orders (enterprise customers only)</li>
                </ul>

                <h4>Refunds and Cancellations</h4>
                <ul>
                  <li>
                    <strong>Cancellation:</strong> You may cancel your
                    subscription at any time
                  </li>
                  <li>
                    <strong>Effective Date:</strong> Cancellations take effect
                    at the end of the current billing period
                  </li>
                  <li>
                    <strong>Refund Policy:</strong> Pro-rated refunds for annual
                    plans cancelled within 30 days
                  </li>
                  <li>
                    <strong>No Refunds:</strong> Monthly plans and usage-based
                    charges are non-refundable
                  </li>
                  <li>
                    <strong>Free Trial:</strong> Free trials can be cancelled
                    without charge
                  </li>
                </ul>

                <h4>Payment Failures</h4>
                <p>If payment fails:</p>
                <ul>
                  <li>We'll attempt to process payment multiple times</li>
                  <li>You'll receive notifications about payment failures</li>
                  <li>
                    Service may be suspended after 7 days of failed payment
                  </li>
                  <li>
                    Account may be terminated after 30 days of non-payment
                  </li>
                  <li>Late fees may apply as permitted by law</li>
                </ul>

                <h4>Usage Overages</h4>
                <p>For plans with usage limits:</p>
                <ul>
                  <li>Overage charges apply for usage beyond plan limits</li>
                  <li>You'll receive notifications approaching usage limits</li>
                  <li>You can upgrade your plan to avoid overage charges</li>
                  <li>
                    Overage rates are published in our pricing documentation
                  </li>
                </ul>

                <div className="alert alert-info">
                  <strong>💳 Billing Support:</strong> For billing questions or
                  payment issues, contact our billing team at
                  billing@site-analyser.com or through your account dashboard.
                </div>
              </section>

              <section id="intellectual-property" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  7. Intellectual Property Rights
                </h2>

                <h4>Our Intellectual Property</h4>
                <p>Site-Analyser owns all rights, title, and interest in:</p>
                <ul>
                  <li>
                    <strong>Software and Technology:</strong> Our scanning
                    engines, algorithms, and analysis tools
                  </li>
                  <li>
                    <strong>Trademarks:</strong> Site-Analyser name, logos, and
                    branded materials
                  </li>
                  <li>
                    <strong>Copyrights:</strong> Documentation, reports, user
                    interfaces, and content
                  </li>
                  <li>
                    <strong>Trade Secrets:</strong> Proprietary methodologies
                    and business processes
                  </li>
                  <li>
                    <strong>Patents:</strong> Any patented technologies
                    incorporated in our Service
                  </li>
                </ul>

                <h4>License to Use</h4>
                <p>
                  We grant you a limited, non-exclusive, non-transferable
                  license to:
                </p>
                <ul>
                  <li>Access and use our Service according to these Terms</li>
                  <li>Generate and download reports for your authorized use</li>
                  <li>Use our API within your subscription limits</li>
                  <li>Display our trademarks solely to identify our Service</li>
                </ul>

                <h4>Restrictions</h4>
                <p>You may not:</p>
                <ul>
                  <li>
                    <strong>Reverse Engineer:</strong> Attempt to discover our
                    source code or algorithms
                  </li>
                  <li>
                    <strong>Create Derivatives:</strong> Modify, adapt, or
                    create derivative works
                  </li>
                  <li>
                    <strong>Redistribute:</strong> Resell, sublicense, or
                    distribute our Service
                  </li>
                  <li>
                    <strong>Remove Notices:</strong> Remove or obscure
                    intellectual property notices
                  </li>
                  <li>
                    <strong>Compete:</strong> Use our Service to build competing
                    products
                  </li>
                </ul>

                <h4>User Content</h4>
                <p>
                  You retain ownership of content you provide, but grant us:
                </p>
                <ul>
                  <li>Rights to process your data to provide the Service</li>
                  <li>
                    Permission to use aggregated, anonymized data for service
                    improvement
                  </li>
                  <li>
                    Authority to display your content in reports and dashboards
                  </li>
                  <li>License to backup and store your data as necessary</li>
                </ul>

                <h4>Third-Party Content</h4>
                <p>Our Service may include third-party content:</p>
                <ul>
                  <li>
                    Open-source libraries and components (licensed separately)
                  </li>
                  <li>Vulnerability databases and threat intelligence feeds</li>
                  <li>Integration partner content and data</li>
                  <li>User-generated content in community features</li>
                </ul>

                <h4>DMCA and Copyright Claims</h4>
                <p>If you believe your copyright has been infringed:</p>
                <ul>
                  <li>Submit a DMCA notice to dmca@site-analyser.com</li>
                  <li>
                    Include all required information per DMCA requirements
                  </li>
                  <li>We will investigate and respond promptly</li>
                  <li>False claims may result in liability for damages</li>
                </ul>
              </section>

              <section id="data-ownership" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  8. Data Ownership and Usage
                </h2>

                <h4>Your Data</h4>
                <p>You retain ownership and control over:</p>
                <ul>
                  <li>
                    <strong>Scan Targets:</strong> URLs and systems you submit
                    for scanning
                  </li>
                  <li>
                    <strong>Configuration Data:</strong> Scan settings and
                    preferences
                  </li>
                  <li>
                    <strong>Business Information:</strong> Company details and
                    contact information
                  </li>
                  <li>
                    <strong>Custom Content:</strong> Reports, notes, and
                    annotations you create
                  </li>
                </ul>

                <h4>Scan Results and Reports</h4>
                <p>Scan results and reports are considered your data, but:</p>
                <ul>
                  <li>
                    We may use anonymized, aggregated data for service
                    improvement
                  </li>
                  <li>
                    Vulnerability patterns may inform our threat intelligence
                  </li>
                  <li>
                    Statistical analysis helps improve our detection algorithms
                  </li>
                  <li>
                    We never share your specific findings with third parties
                  </li>
                </ul>

                <h4>Data Processing Rights</h4>
                <p>By using our Service, you grant us the right to:</p>
                <ul>
                  <li>
                    Process your data to provide scanning and analysis services
                  </li>
                  <li>Store and backup your data for service reliability</li>
                  <li>Access your data for customer support purposes</li>
                  <li>Use aggregated data for research and development</li>
                </ul>

                <h4>Data Export and Portability</h4>
                <p>You can export your data in standard formats:</p>
                <ul>
                  <li>
                    <strong>Reports:</strong> PDF, JSON, CSV, and XML formats
                  </li>
                  <li>
                    <strong>Raw Data:</strong> API access to all your scan data
                  </li>
                  <li>
                    <strong>Configuration:</strong> Settings and preferences
                    export
                  </li>
                  <li>
                    <strong>Account Data:</strong> Complete data export upon
                    request
                  </li>
                </ul>

                <h4>Data Deletion</h4>
                <p>You can delete your data at any time:</p>
                <ul>
                  <li>
                    Individual scan results can be deleted from your dashboard
                  </li>
                  <li>Complete account deletion removes all associated data</li>
                  <li>
                    Deleted data is removed from active systems within 30 days
                  </li>
                  <li>
                    Backup retention follows our published data retention policy
                  </li>
                </ul>

                <h4>Third-Party Data</h4>
                <p>Our Service incorporates data from third-party sources:</p>
                <ul>
                  <li>
                    <strong>Vulnerability Databases:</strong> CVE, NVD, and
                    proprietary threat feeds
                  </li>
                  <li>
                    <strong>Reputation Services:</strong> Domain and IP
                    reputation data
                  </li>
                  <li>
                    <strong>Certificate Authorities:</strong> SSL/TLS
                    certificate validation data
                  </li>
                  <li>
                    <strong>Threat Intelligence:</strong> Indicators of
                    compromise and attack patterns
                  </li>
                </ul>

                <div className="alert alert-success">
                  <strong>🔒 Data Protection:</strong> Your scan results and
                  sensitive data are never shared with third parties or used for
                  purposes other than providing you with our security services.
                </div>
              </section>

              <section id="disclaimers" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  9. Disclaimers and Limitations
                </h2>

                <h4>Service Disclaimer</h4>
                <p>
                  OUR SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT
                  WARRANTIES OF ANY KIND. WE DISCLAIM ALL WARRANTIES, EXPRESS OR
                  IMPLIED, INCLUDING:
                </p>
                <ul>
                  <li>
                    <strong>Merchantability:</strong> Fitness for a particular
                    purpose
                  </li>
                  <li>
                    <strong>Accuracy:</strong> Completeness or accuracy of scan
                    results
                  </li>
                  <li>
                    <strong>Reliability:</strong> Uninterrupted or error-free
                    operation
                  </li>
                  <li>
                    <strong>Security:</strong> Complete detection of all
                    vulnerabilities
                  </li>
                  <li>
                    <strong>Compliance:</strong> Meeting all regulatory
                    requirements
                  </li>
                </ul>

                <h4>Scanning Limitations</h4>
                <p>Our scanning technology has inherent limitations:</p>
                <ul>
                  <li>False positives and false negatives may occur</li>
                  <li>New vulnerabilities may not be immediately detectable</li>
                  <li>Some security measures may prevent effective scanning</li>
                  <li>
                    Dynamic content and complex applications may not be fully
                    analyzed
                  </li>
                  <li>Zero-day vulnerabilities may not be detected</li>
                </ul>

                <h4>Professional Advice Disclaimer</h4>
                <p>Our Service provides technical analysis but:</p>
                <ul>
                  <li>Does not constitute professional security consulting</li>
                  <li>Should not be the sole basis for security decisions</li>
                  <li>Does not replace professional security assessments</li>
                  <li>
                    May not identify all security risks or vulnerabilities
                  </li>
                  <li>Should be supplemented with other security measures</li>
                </ul>

                <h4>Limitation of Liability</h4>
                <p>TO THE MAXIMUM EXTENT PERMITTED BY LAW:</p>
                <ul>
                  <li>
                    OUR LIABILITY IS LIMITED TO THE AMOUNT YOU PAID IN THE LAST
                    12 MONTHS
                  </li>
                  <li>
                    WE ARE NOT LIABLE FOR INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
                    DAMAGES
                  </li>
                  <li>
                    WE ARE NOT LIABLE FOR DATA LOSS, BUSINESS INTERRUPTION, OR
                    LOST PROFITS
                  </li>
                  <li>WE ARE NOT LIABLE FOR THIRD-PARTY ACTIONS OR FAILURES</li>
                  <li>SOME JURISDICTIONS MAY NOT ALLOW THESE LIMITATIONS</li>
                </ul>

                <h4>Third-Party Services</h4>
                <p>We integrate with third-party services but:</p>
                <ul>
                  <li>
                    Are not responsible for their availability or accuracy
                  </li>
                  <li>
                    Do not warrant the security or reliability of external
                    services
                  </li>
                  <li>Are not liable for any third-party service failures</li>
                  <li>May discontinue integrations without notice</li>
                </ul>

                <h4>Force Majeure</h4>
                <p>We are not liable for delays or failures due to:</p>
                <ul>
                  <li>Natural disasters, acts of God, or extreme weather</li>
                  <li>War, terrorism, civil unrest, or government actions</li>
                  <li>
                    Internet outages, cyber attacks, or infrastructure failures
                  </li>
                  <li>Pandemic, epidemic, or public health emergencies</li>
                  <li>Other circumstances beyond our reasonable control</li>
                </ul>

                <div className="alert alert-warning">
                  <strong>⚠️ Important Notice:</strong> Security scanning is one
                  component of a comprehensive security program. Our service
                  should complement, not replace, other security measures and
                  professional security expertise.
                </div>
              </section>

              <section id="indemnification" className="mb-5">
                <h2 className="h3 text-primary mb-3">10. Indemnification</h2>

                <h4>Your Indemnification Obligations</h4>
                <p>
                  You agree to defend, indemnify, and hold harmless
                  Site-Analyser, its officers, directors, employees, and agents
                  from any claims, damages, losses, and expenses (including
                  attorney fees) arising from:
                </p>

                <ul>
                  <li>
                    <strong>Unauthorized Scanning:</strong> Scanning systems
                    without proper authorization
                  </li>
                  <li>
                    <strong>Violation of Terms:</strong> Breach of these Terms
                    or our Acceptable Use Policy
                  </li>
                  <li>
                    <strong>Illegal Activities:</strong> Use of our Service for
                    unlawful purposes
                  </li>
                  <li>
                    <strong>Third-Party Claims:</strong> Claims that your use
                    infringes third-party rights
                  </li>
                  <li>
                    <strong>Data Breaches:</strong> Security incidents resulting
                    from your negligence
                  </li>
                  <li>
                    <strong>Misrepresentation:</strong> False or misleading
                    information you provide
                  </li>
                </ul>

                <h4>Our Indemnification Obligations</h4>
                <p>
                  We will defend and indemnify you against claims that our
                  Service infringes third-party intellectual property rights,
                  provided that:
                </p>
                <ul>
                  <li>You promptly notify us of any such claim</li>
                  <li>
                    You give us sole control of the defense and settlement
                  </li>
                  <li>You provide reasonable cooperation in the defense</li>
                  <li>Your use of the Service complies with these Terms</li>
                </ul>

                <h4>Indemnification Procedures</h4>
                <p>For any indemnification claim:</p>
                <ul>
                  <li>
                    The indemnified party must provide prompt written notice
                  </li>
                  <li>
                    The indemnifying party may assume control of the defense
                  </li>
                  <li>Both parties must cooperate in good faith</li>
                  <li>Settlement requires consent of both parties</li>
                </ul>

                <h4>Limitations</h4>
                <p>
                  Indemnification obligations do not apply to claims arising
                  from:
                </p>
                <ul>
                  <li>Modifications you make to our Service</li>
                  <li>
                    Use of our Service in combination with unauthorized products
                  </li>
                  <li>
                    Continued use after we notify you to discontinue due to
                    infringement
                  </li>
                  <li>Use not in accordance with these Terms</li>
                </ul>
              </section>

              <section id="termination" className="mb-5">
                <h2 className="h3 text-primary mb-3">11. Termination</h2>

                <h4>Termination by You</h4>
                <p>You may terminate your account at any time by:</p>
                <ul>
                  <li>Using the account deletion feature in your dashboard</li>
                  <li>Contacting our customer support team</li>
                  <li>
                    Cancelling your subscription (service continues until period
                    end)
                  </li>
                  <li>Following our published account closure procedures</li>
                </ul>

                <h4>Termination by Us</h4>
                <p>We may terminate or suspend your account immediately if:</p>
                <ul>
                  <li>
                    <strong>Terms Violation:</strong> You breach these Terms or
                    our policies
                  </li>
                  <li>
                    <strong>Illegal Activity:</strong> You use our Service for
                    unlawful purposes
                  </li>
                  <li>
                    <strong>Payment Default:</strong> You fail to pay required
                    fees
                  </li>
                  <li>
                    <strong>Security Risk:</strong> Your account poses a
                    security risk
                  </li>
                  <li>
                    <strong>Abuse:</strong> You abuse our Service or support
                    team
                  </li>
                  <li>
                    <strong>Inactivity:</strong> Your account is inactive for
                    extended periods
                  </li>
                </ul>

                <h4>Effects of Termination</h4>
                <p>Upon termination:</p>
                <ul>
                  <li>
                    Your access to the Service will be immediately revoked
                  </li>
                  <li>
                    All data will be deleted according to our retention policy
                  </li>
                  <li>
                    You remain liable for all charges incurred before
                    termination
                  </li>
                  <li>
                    Ongoing obligations under these Terms survive termination
                  </li>
                  <li>You must cease all use of our intellectual property</li>
                </ul>

                <h4>Data Retention After Termination</h4>
                <p>After account termination:</p>
                <ul>
                  <li>
                    <strong>Immediate:</strong> Active data access is revoked
                  </li>
                  <li>
                    <strong>30 Days:</strong> Data remains available for
                    recovery
                  </li>
                  <li>
                    <strong>90 Days:</strong> Complete data deletion from active
                    systems
                  </li>
                  <li>
                    <strong>Legal Holds:</strong> Some data may be retained for
                    legal compliance
                  </li>
                </ul>

                <h4>Survival</h4>
                <p>The following sections survive termination:</p>
                <ul>
                  <li>Payment obligations for services rendered</li>
                  <li>Intellectual property rights and restrictions</li>
                  <li>Indemnification obligations</li>
                  <li>Limitation of liability and disclaimers</li>
                  <li>Governing law and dispute resolution</li>
                </ul>

                <div className="alert alert-info">
                  <strong>💾 Data Backup:</strong> We recommend exporting your
                  data before terminating your account. After the retention
                  period, data cannot be recovered.
                </div>
              </section>

              <section id="governing-law" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  12. Governing Law and Disputes
                </h2>

                <h4>Governing Law</h4>
                <p>
                  These Terms are governed by and construed in accordance with
                  the laws of the State of Delaware, United States, without
                  regard to conflict of law principles.
                </p>

                <h4>Jurisdiction</h4>
                <p>
                  Any legal action or proceeding arising under these Terms will
                  be brought exclusively in the federal or state courts located
                  in Delaware, and you consent to the jurisdiction of such
                  courts.
                </p>

                <h4>Dispute Resolution Process</h4>
                <p>
                  Before initiating legal proceedings, you agree to attempt
                  resolution through:
                </p>
                <ol>
                  <li>
                    <strong>Direct Communication:</strong> Contact our legal
                    team at legal@site-analyser.com
                  </li>
                  <li>
                    <strong>Good Faith Negotiation:</strong> 30-day period for
                    informal resolution
                  </li>
                  <li>
                    <strong>Mediation:</strong> Non-binding mediation if
                    informal resolution fails
                  </li>
                  <li>
                    <strong>Arbitration:</strong> Binding arbitration for claims
                    under $75,000
                  </li>
                </ol>

                <h4>Arbitration Agreement</h4>
                <p>
                  For claims under $75,000, you agree to binding arbitration
                  under the rules of the American Arbitration Association (AAA),
                  except:
                </p>
                <ul>
                  <li>Claims for injunctive or equitable relief</li>
                  <li>Small claims court actions</li>
                  <li>Intellectual property disputes</li>
                  <li>Class action lawsuits (which are waived)</li>
                </ul>

                <h4>Class Action Waiver</h4>
                <p>
                  You waive the right to participate in class actions,
                  collective actions, or representative proceedings. All
                  disputes must be brought individually.
                </p>

                <h4>Time Limitation</h4>
                <p>
                  Any claim arising from these Terms must be filed within one
                  (1) year after the claim arose, or it will be permanently
                  barred.
                </p>

                <h4>International Users</h4>
                <p>If you are located outside the United States:</p>
                <ul>
                  <li>These Terms still apply to your use of our Service</li>
                  <li>Local laws may provide additional protections</li>
                  <li>
                    We will comply with applicable international data protection
                    laws
                  </li>
                  <li>
                    Currency conversions will be made at prevailing exchange
                    rates
                  </li>
                </ul>
              </section>

              <section id="miscellaneous" className="mb-5">
                <h2 className="h3 text-primary mb-3">13. Miscellaneous</h2>

                <h4>Entire Agreement</h4>
                <p>
                  These Terms, together with our Privacy Policy and other
                  referenced policies, constitute the complete agreement between
                  you and Site-Analyser regarding the Service.
                </p>

                <h4>Severability</h4>
                <p>
                  If any provision of these Terms is found unenforceable, the
                  remaining provisions will continue in full force and effect,
                  and the unenforceable provision will be modified to be
                  enforceable while preserving its intent.
                </p>

                <h4>Waiver</h4>
                <p>
                  Our failure to enforce any provision of these Terms does not
                  constitute a waiver of our right to enforce that provision in
                  the future or any other provision.
                </p>

                <h4>Assignment</h4>
                <p>
                  You may not assign these Terms or your account without our
                  written consent. We may assign these Terms at any time,
                  including in connection with a merger, acquisition, or sale of
                  assets.
                </p>

                <h4>Third-Party Beneficiaries</h4>
                <p>
                  These Terms do not create any third-party beneficiary rights
                  except as expressly stated.
                </p>

                <h4>Notices</h4>
                <p>
                  Notices to you will be sent to your registered email address.
                  Notices to us should be sent to legal@site-analyser.com.
                </p>

                <h4>Language</h4>
                <p>
                  These Terms are written in English. If translated into other
                  languages, the English version controls in case of conflicts.
                </p>

                <h4>Force Majeure</h4>
                <p>
                  Neither party is liable for delays or failures due to
                  circumstances beyond their reasonable control, including
                  natural disasters, government actions, or infrastructure
                  failures.
                </p>

                <h4>Export Controls</h4>
                <p>
                  Our Service is subject to U.S. export control laws. You agree
                  not to export or re-export the Service to restricted countries
                  or persons.
                </p>

                <h4>Government Users</h4>
                <p>
                  If you are a U.S. government entity, our Service is provided
                  as "Commercial Computer Software" subject to the rights and
                  restrictions of these Terms.
                </p>
              </section>

              <section id="contact-information" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  14. Contact Information
                </h2>

                <p>
                  For questions about these Terms of Service or to report
                  violations, please contact us:
                </p>

                <div className="row">
                  <div className="col-md-6">
                    <h5>Legal Team</h5>
                    <ul className="list-unstyled">
                      <li>
                        <strong>Email:</strong> legal@site-analyser.com
                      </li>
                      <li>
                        <strong>Response Time:</strong> Within 5 business days
                      </li>
                      <li>
                        <strong>Phone:</strong> +1 (555) 123-4567
                      </li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <h5>Business Address</h5>
                    <address>
                      Site-Analyser, Inc.
                      <br />
                      Legal Department
                      <br />
                      123 Security Street, Suite 456
                      <br />
                      Tech City, TC 12345
                      <br />
                      United States
                    </address>
                  </div>
                </div>

                <h5>Registered Agent</h5>
                <address>
                  Corporation Service Company
                  <br />
                  251 Little Falls Drive
                  <br />
                  Wilmington, DE 19808
                  <br />
                  United States
                </address>

                <h5>Emergency Contacts</h5>
                <ul>
                  <li>
                    <strong>Security Issues:</strong> security@site-analyser.com
                  </li>
                  <li>
                    <strong>DMCA Claims:</strong> dmca@site-analyser.com
                  </li>
                  <li>
                    <strong>Law Enforcement:</strong> legal@site-analyser.com
                  </li>
                  <li>
                    <strong>Press Inquiries:</strong> press@site-analyser.com
                  </li>
                </ul>

                <div className="alert alert-success">
                  <strong>📞 Support:</strong> For general customer support or
                  technical questions, please use our help center or contact
                  support@site-analyser.com.
                </div>
              </section>

              {/* Footer */}
              <div className="border-top pt-4 mt-5">
                <div className="row align-items-center">
                  <div className="col-lg-8">
                    <p className="text-muted mb-2">
                      These Terms of Service are part of our legal framework to
                      ensure fair and secure use of our platform. We encourage
                      you to review them periodically as they may be updated to
                      reflect changes in our services or applicable law.
                    </p>
                    <p className="text-muted small mb-0">
                      Last updated: June 1, 2025 | Version 3.2 |
                      <button
                        className="btn btn-link btn-sm p-0 text-muted"
                        onClick={() =>
                          window.open("/legal/terms-history", "_blank")
                        }
                      >
                        View Version History
                      </button>
                    </p>
                  </div>
                  <div className="col-lg-4 mt-3 mt-lg-0">
                    <div className="d-grid gap-2 d-md-flex justify-content-lg-end">
                      <Link
                        to="/privacy-policy"
                        className="btn btn-outline-primary"
                      >
                        View Privacy Policy
                      </Link>
                      <button
                        className="btn btn-secondary"
                        onClick={() => window.print()}
                      >
                        Print Terms
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TermsOfService;
