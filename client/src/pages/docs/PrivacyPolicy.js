// frontend/src/pages/docs/PrivacyPolicy.js

import { useEffect } from "react";
import { Link } from "react-router-dom";

const PrivacyPolicy = () => {
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
                  Privacy Policy
                </h1>
                <p className="lead text-muted">
                  Your privacy is important to us. This Privacy Policy explains
                  how Site-Analyser collects, uses, and protects your
                  information.
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
                    onClick={() => scrollToSection("information-we-collect")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    1. Information We Collect
                  </button>
                  <button
                    onClick={() => scrollToSection("how-we-use-information")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    2. How We Use Your Information
                  </button>
                  <button
                    onClick={() => scrollToSection("information-sharing")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    3. Information Sharing and Disclosure
                  </button>
                  <button
                    onClick={() => scrollToSection("data-security")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    4. Data Security
                  </button>
                  <button
                    onClick={() => scrollToSection("data-retention")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    5. Data Retention
                  </button>
                  <button
                    onClick={() => scrollToSection("your-rights")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    6. Your Rights and Choices
                  </button>
                  <button
                    onClick={() => scrollToSection("international-transfers")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    7. International Data Transfers
                  </button>
                  <button
                    onClick={() => scrollToSection("children-privacy")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    8. Children's Privacy
                  </button>
                  <button
                    onClick={() => scrollToSection("changes-to-policy")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    9. Changes to This Policy
                  </button>
                  <button
                    onClick={() => scrollToSection("contact-us")}
                    className="list-group-item list-group-item-action border-0 text-start"
                  >
                    10. Contact Us
                  </button>
                </div>
              </div>

              {/* Content Sections */}
              <section id="information-we-collect" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  1. Information We Collect
                </h2>

                <h4>Account Information</h4>
                <p>
                  When you create an account with Site-Analyser, we collect:
                </p>
                <ul>
                  <li>
                    <strong>Personal Details:</strong> Name, email address,
                    company name (optional)
                  </li>
                  <li>
                    <strong>Authentication Data:</strong> Password (encrypted),
                    two-factor authentication settings
                  </li>
                  <li>
                    <strong>Billing Information:</strong> Payment method
                    details, billing address (processed securely through our
                    payment processors)
                  </li>
                  <li>
                    <strong>Communication Preferences:</strong> Email
                    preferences, notification settings
                  </li>
                </ul>

                <h4>Scanning Data</h4>
                <p>To provide our security scanning services, we collect:</p>
                <ul>
                  <li>
                    <strong>Target URLs:</strong> Websites and domains you
                    submit for scanning
                  </li>
                  <li>
                    <strong>Scan Results:</strong> Security vulnerabilities,
                    configuration data, and technical findings
                  </li>
                  <li>
                    <strong>Website Content:</strong> Publicly accessible
                    content necessary for security analysis
                  </li>
                  <li>
                    <strong>Technical Metadata:</strong> HTTP headers, SSL
                    certificates, server responses
                  </li>
                </ul>

                <h4>Usage Information</h4>
                <p>
                  We automatically collect information about how you use our
                  service:
                </p>
                <ul>
                  <li>
                    <strong>Log Data:</strong> IP addresses, browser type,
                    operating system, pages visited
                  </li>
                  <li>
                    <strong>Analytics Data:</strong> Feature usage, performance
                    metrics, error logs
                  </li>
                  <li>
                    <strong>API Usage:</strong> API calls, request patterns,
                    response times
                  </li>
                  <li>
                    <strong>Device Information:</strong> Device type, screen
                    resolution, browser capabilities
                  </li>
                </ul>

                <h4>Cookies and Tracking Technologies</h4>
                <p>We use cookies and similar technologies to:</p>
                <ul>
                  <li>Maintain your login session</li>
                  <li>Remember your preferences and settings</li>
                  <li>Analyze service usage and performance</li>
                  <li>Provide personalized content and recommendations</li>
                </ul>

                <div className="alert alert-info">
                  <strong>🍪 Cookie Policy:</strong> You can control cookie
                  settings through your browser. However, disabling certain
                  cookies may limit service functionality.
                </div>
              </section>

              <section id="how-we-use-information" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  2. How We Use Your Information
                </h2>

                <h4>Service Provision</h4>
                <ul>
                  <li>Perform security scans and generate reports</li>
                  <li>Provide AI-powered analysis and recommendations</li>
                  <li>Maintain and improve our scanning algorithms</li>
                  <li>Deliver compliance assessments and reporting</li>
                </ul>

                <h4>Account Management</h4>
                <ul>
                  <li>Create and maintain your user account</li>
                  <li>Process payments and manage billing</li>
                  <li>Provide customer support and technical assistance</li>
                  <li>Send important service notifications and updates</li>
                </ul>

                <h4>Service Improvement</h4>
                <ul>
                  <li>Analyze usage patterns to enhance user experience</li>
                  <li>Develop new features and capabilities</li>
                  <li>Conduct security research and threat intelligence</li>
                  <li>Monitor service performance and reliability</li>
                </ul>

                <h4>Communication</h4>
                <ul>
                  <li>Send security alerts and scan notifications</li>
                  <li>Provide educational content and security tips</li>
                  <li>Share product updates and new features</li>
                  <li>Respond to your inquiries and support requests</li>
                </ul>

                <h4>Legal and Compliance</h4>
                <ul>
                  <li>Comply with applicable laws and regulations</li>
                  <li>Protect against fraud and abuse</li>
                  <li>Enforce our Terms of Service</li>
                  <li>Respond to legal requests and court orders</li>
                </ul>
              </section>

              <section id="information-sharing" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  3. Information Sharing and Disclosure
                </h2>

                <p>
                  We respect your privacy and do not sell your personal
                  information. We may share information in the following
                  circumstances:
                </p>

                <h4>Service Providers</h4>
                <p>
                  We work with trusted third-party service providers who assist
                  us in operating our service:
                </p>
                <ul>
                  <li>
                    <strong>Cloud Infrastructure:</strong> AWS, Google Cloud for
                    hosting and storage
                  </li>
                  <li>
                    <strong>Payment Processing:</strong> Stripe, PayPal for
                    secure payment handling
                  </li>
                  <li>
                    <strong>Email Services:</strong> SendGrid, Mailgun for
                    transactional emails
                  </li>
                  <li>
                    <strong>Analytics:</strong> Google Analytics, Mixpanel for
                    usage analysis
                  </li>
                  <li>
                    <strong>Customer Support:</strong> Zendesk, Intercom for
                    support ticket management
                  </li>
                </ul>

                <p>
                  These providers are contractually bound to protect your
                  information and use it only for specified purposes.
                </p>

                <h4>Third-Party Integrations</h4>
                <p>
                  When you enable integrations with external services, we may
                  share relevant data:
                </p>
                <ul>
                  <li>
                    <strong>Shodan:</strong> Domain/IP information for enhanced
                    scanning
                  </li>
                  <li>
                    <strong>VirusTotal:</strong> URLs and file hashes for
                    malware detection
                  </li>
                  <li>
                    <strong>SSL Labs:</strong> Domain information for SSL
                    analysis
                  </li>
                </ul>

                <h4>Legal Requirements</h4>
                <p>We may disclose information when required by law or to:</p>
                <ul>
                  <li>
                    Comply with legal process, court orders, or government
                    requests
                  </li>
                  <li>Protect our rights, property, or safety</li>
                  <li>Investigate and prevent fraud or security threats</li>
                  <li>Enforce our Terms of Service</li>
                </ul>

                <h4>Business Transfers</h4>
                <p>
                  In the event of a merger, acquisition, or sale of assets, your
                  information may be transferred to the new entity, subject to
                  the same privacy protections.
                </p>

                <h4>Aggregated and Anonymized Data</h4>
                <p>We may share aggregated, anonymized data for:</p>
                <ul>
                  <li>Security research and threat intelligence</li>
                  <li>Industry benchmarking and reports</li>
                  <li>Product development and improvement</li>
                </ul>

                <div className="alert alert-warning">
                  <strong>⚠️ Important:</strong> We never share your specific
                  vulnerability findings or scan results with third parties
                  without your explicit consent.
                </div>
              </section>

              <section id="data-security" className="mb-5">
                <h2 className="h3 text-primary mb-3">4. Data Security</h2>

                <p>
                  We implement comprehensive security measures to protect your
                  information:
                </p>

                <h4>Technical Safeguards</h4>
                <ul>
                  <li>
                    <strong>Encryption:</strong> All data is encrypted in
                    transit (TLS 1.3) and at rest (AES-256)
                  </li>
                  <li>
                    <strong>Access Controls:</strong> Multi-factor
                    authentication, role-based access, principle of least
                    privilege
                  </li>
                  <li>
                    <strong>Network Security:</strong> Firewalls, intrusion
                    detection, DDoS protection
                  </li>
                  <li>
                    <strong>Secure Development:</strong> Security code reviews,
                    dependency scanning, penetration testing
                  </li>
                </ul>

                <h4>Operational Safeguards</h4>
                <ul>
                  <li>
                    <strong>Employee Training:</strong> Regular security
                    awareness and privacy training
                  </li>
                  <li>
                    <strong>Background Checks:</strong> Screening for employees
                    with data access
                  </li>
                  <li>
                    <strong>Access Monitoring:</strong> Logging and monitoring
                    of all data access
                  </li>
                  <li>
                    <strong>Incident Response:</strong> Established procedures
                    for security incidents
                  </li>
                </ul>

                <h4>Infrastructure Security</h4>
                <ul>
                  <li>
                    <strong>SOC 2 Type II:</strong> Compliance with industry
                    security standards
                  </li>
                  <li>
                    <strong>ISO 27001:</strong> Information security management
                    certification
                  </li>
                  <li>
                    <strong>Regular Audits:</strong> Third-party security
                    assessments and penetration tests
                  </li>
                  <li>
                    <strong>Vulnerability Management:</strong> Continuous
                    monitoring and patching
                  </li>
                </ul>

                <h4>Data Isolation</h4>
                <ul>
                  <li>Customer data is logically separated and isolated</li>
                  <li>Multi-tenant architecture with strict access controls</li>
                  <li>Regular backup and disaster recovery testing</li>
                  <li>Geographic data residency options</li>
                </ul>

                <div className="alert alert-success">
                  <strong>🔒 Security Commitment:</strong> We maintain the same
                  security standards for your data that we recommend for our
                  customers' websites.
                </div>
              </section>

              <section id="data-retention" className="mb-5">
                <h2 className="h3 text-primary mb-3">5. Data Retention</h2>

                <p>
                  We retain your information for as long as necessary to provide
                  our services and comply with legal obligations:
                </p>

                <h4>Account Data</h4>
                <ul>
                  <li>
                    <strong>Active Accounts:</strong> Retained while your
                    account is active
                  </li>
                  <li>
                    <strong>Closed Accounts:</strong> Personal data deleted
                    within 90 days of account closure
                  </li>
                  <li>
                    <strong>Billing Records:</strong> Retained for 7 years for
                    tax and accounting purposes
                  </li>
                </ul>

                <h4>Scan Data</h4>
                <ul>
                  <li>
                    <strong>Scan Results:</strong> Retained based on your
                    subscription plan (90 days to 2 years)
                  </li>
                  <li>
                    <strong>Historical Data:</strong> Aggregated trends data
                    retained for service improvement
                  </li>
                  <li>
                    <strong>Compliance Reports:</strong> Retained for 7 years to
                    support audit requirements
                  </li>
                </ul>

                <h4>Usage Data</h4>
                <ul>
                  <li>
                    <strong>Log Files:</strong> Retained for 1 year for security
                    and troubleshooting
                  </li>
                  <li>
                    <strong>Analytics Data:</strong> Aggregated data retained
                    indefinitely for service improvement
                  </li>
                  <li>
                    <strong>Support Tickets:</strong> Retained for 3 years for
                    quality assurance
                  </li>
                </ul>

                <h4>Data Deletion</h4>
                <p>You can request deletion of your data at any time by:</p>
                <ul>
                  <li>Using the account deletion feature in your dashboard</li>
                  <li>
                    Contacting our privacy team at privacy@site-analyser.com
                  </li>
                  <li>
                    Following the data subject request process outlined below
                  </li>
                </ul>

                <div className="table-responsive mt-3">
                  <table className="table table-striped">
                    <thead>
                      <tr>
                        <th>Data Type</th>
                        <th>Retention Period</th>
                        <th>Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>Account Information</td>
                        <td>Duration of account + 90 days</td>
                        <td>Service provision</td>
                      </tr>
                      <tr>
                        <td>Scan Results</td>
                        <td>Plan-dependent (90 days - 2 years)</td>
                        <td>Historical analysis</td>
                      </tr>
                      <tr>
                        <td>Billing Records</td>
                        <td>7 years</td>
                        <td>Tax/legal compliance</td>
                      </tr>
                      <tr>
                        <td>Support Tickets</td>
                        <td>3 years</td>
                        <td>Quality assurance</td>
                      </tr>
                      <tr>
                        <td>Usage Logs</td>
                        <td>1 year</td>
                        <td>Security/troubleshooting</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </section>

              <section id="your-rights" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  6. Your Rights and Choices
                </h2>

                <p>
                  You have several rights regarding your personal information:
                </p>

                <h4>Access and Portability</h4>
                <ul>
                  <li>
                    <strong>View Your Data:</strong> Access all personal
                    information we have about you
                  </li>
                  <li>
                    <strong>Export Data:</strong> Download your data in
                    machine-readable formats
                  </li>
                  <li>
                    <strong>Account Dashboard:</strong> View and manage your
                    information through your account settings
                  </li>
                </ul>

                <h4>Correction and Updates</h4>
                <ul>
                  <li>
                    <strong>Update Profile:</strong> Modify your account
                    information at any time
                  </li>
                  <li>
                    <strong>Correct Errors:</strong> Request correction of
                    inaccurate information
                  </li>
                  <li>
                    <strong>Real-time Updates:</strong> Changes take effect
                    immediately
                  </li>
                </ul>

                <h4>Deletion and Erasure</h4>
                <ul>
                  <li>
                    <strong>Account Deletion:</strong> Delete your entire
                    account and associated data
                  </li>
                  <li>
                    <strong>Selective Deletion:</strong> Remove specific scan
                    results or reports
                  </li>
                  <li>
                    <strong>Right to be Forgotten:</strong> Request complete
                    erasure of your data
                  </li>
                </ul>

                <h4>Processing Restrictions</h4>
                <ul>
                  <li>
                    <strong>Opt-out:</strong> Withdraw consent for marketing
                    communications
                  </li>
                  <li>
                    <strong>Object to Processing:</strong> Object to certain
                    uses of your data
                  </li>
                  <li>
                    <strong>Restrict Processing:</strong> Limit how we use your
                    information
                  </li>
                </ul>

                <h4>Communication Preferences</h4>
                <ul>
                  <li>
                    <strong>Email Preferences:</strong> Choose which emails you
                    receive
                  </li>
                  <li>
                    <strong>Notification Settings:</strong> Control scan alerts
                    and reports
                  </li>
                  <li>
                    <strong>Marketing Opt-out:</strong> Unsubscribe from
                    promotional content
                  </li>
                </ul>

                <h4>Making Requests</h4>
                <p>To exercise your rights, you can:</p>
                <ol>
                  <li>
                    Use the self-service options in your account dashboard
                  </li>
                  <li>Email our privacy team at privacy@site-analyser.com</li>
                  <li>Submit a request through our privacy portal</li>
                  <li>Contact our data protection officer</li>
                </ol>

                <p>
                  We will respond to requests within 30 days and may require
                  identity verification.
                </p>

                <div className="alert alert-info">
                  <strong>🌍 EU/UK Rights:</strong> If you're in the EU or UK,
                  you have additional rights under GDPR/UK GDPR, including the
                  right to lodge a complaint with supervisory authorities.
                </div>
              </section>

              <section id="international-transfers" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  7. International Data Transfers
                </h2>

                <p>
                  Site-Analyser operates globally, and your information may be
                  transferred to and processed in countries other than your own:
                </p>

                <h4>Data Processing Locations</h4>
                <ul>
                  <li>
                    <strong>Primary:</strong> United States (AWS US-East,
                    US-West)
                  </li>
                  <li>
                    <strong>Secondary:</strong> European Union (AWS EU-West-1)
                  </li>
                  <li>
                    <strong>Backup:</strong> Canada (AWS Canada-Central)
                  </li>
                </ul>

                <h4>Transfer Safeguards</h4>
                <p>
                  When transferring data internationally, we ensure appropriate
                  safeguards:
                </p>
                <ul>
                  <li>
                    <strong>Adequacy Decisions:</strong> Transfers to countries
                    with adequate protection
                  </li>
                  <li>
                    <strong>Standard Contractual Clauses:</strong> EU-approved
                    data transfer agreements
                  </li>
                  <li>
                    <strong>Binding Corporate Rules:</strong> Internal data
                    protection standards
                  </li>
                  <li>
                    <strong>Certification Schemes:</strong> Privacy Shield
                    successors and equivalent frameworks
                  </li>
                </ul>

                <h4>Data Residency Options</h4>
                <p>Enterprise customers can request specific data residency:</p>
                <ul>
                  <li>
                    <strong>EU-only Processing:</strong> Data processed and
                    stored within the EU
                  </li>
                  <li>
                    <strong>US-only Processing:</strong> Data kept within US
                    boundaries
                  </li>
                  <li>
                    <strong>Regional Preferences:</strong> Custom data residency
                    requirements
                  </li>
                </ul>

                <div className="alert alert-warning">
                  <strong>⚠️ Note:</strong> Some third-party integrations may
                  require data transfer to their processing locations. We always
                  ensure these transfers comply with applicable data protection
                  laws.
                </div>
              </section>

              <section id="children-privacy" className="mb-5">
                <h2 className="h3 text-primary mb-3">8. Children's Privacy</h2>

                <p>
                  Site-Analyser is designed for business and professional use.
                  We do not knowingly collect information from children under 13
                  (or 16 in the EU).
                </p>

                <h4>Age Verification</h4>
                <ul>
                  <li>
                    Account registration requires confirmation that users are 18
                    or older
                  </li>
                  <li>
                    We may request age verification for accounts that appear to
                    be minors
                  </li>
                  <li>
                    Educational use requires supervision by authorized
                    instructors
                  </li>
                </ul>

                <h4>If We Learn of Children's Information</h4>
                <p>
                  If we discover that we have collected information from a child
                  under the applicable age:
                </p>
                <ul>
                  <li>We will delete the information immediately</li>
                  <li>We will suspend or terminate the account</li>
                  <li>
                    We will notify parents/guardians if contact information is
                    available
                  </li>
                </ul>

                <h4>Parental Rights</h4>
                <p>Parents and guardians can:</p>
                <ul>
                  <li>
                    Request information about data we may have about their child
                  </li>
                  <li>Request deletion of their child's information</li>
                  <li>
                    Refuse further collection of their child's information
                  </li>
                </ul>

                <p>
                  Contact us at privacy@site-analyser.com for any children's
                  privacy concerns.
                </p>
              </section>

              <section id="changes-to-policy" className="mb-5">
                <h2 className="h3 text-primary mb-3">
                  9. Changes to This Policy
                </h2>

                <p>
                  We may update this Privacy Policy periodically to reflect
                  changes in our practices or applicable law.
                </p>

                <h4>Notification Process</h4>
                <ul>
                  <li>
                    <strong>Material Changes:</strong> 30-day advance notice via
                    email and in-app notification
                  </li>
                  <li>
                    <strong>Minor Updates:</strong> Notice posted on our website
                    and in your dashboard
                  </li>
                  <li>
                    <strong>Legal Changes:</strong> Immediate notification if
                    required by law
                  </li>
                </ul>

                <h4>Acceptance of Changes</h4>
                <ul>
                  <li>
                    Continued use of our service constitutes acceptance of
                    changes
                  </li>
                  <li>
                    You may close your account if you disagree with material
                    changes
                  </li>
                  <li>
                    We will obtain explicit consent for changes that require it
                    under applicable law
                  </li>
                </ul>

                <h4>Version History</h4>
                <p>
                  Previous versions of this policy are available upon request.
                  We maintain:
                </p>
                <ul>
                  <li>Complete version history with change dates</li>
                  <li>Summary of material changes for each version</li>
                  <li>Legal basis for processing under each version</li>
                </ul>
              </section>

              <section id="contact-us" className="mb-5">
                <h2 className="h3 text-primary mb-3">10. Contact Us</h2>

                <p>
                  If you have questions about this Privacy Policy or our privacy
                  practices, please contact us:
                </p>

                <div className="row">
                  <div className="col-md-6">
                    <h5>Privacy Team</h5>
                    <ul className="list-unstyled">
                      <li>
                        <strong>Email:</strong> privacy@site-analyser.com
                      </li>
                      <li>
                        <strong>Response Time:</strong> Within 48 hours
                      </li>
                      <li>
                        <strong>Languages:</strong> English, Spanish, French
                      </li>
                    </ul>
                  </div>
                  <div className="col-md-6">
                    <h5>Data Protection Officer</h5>
                    <ul className="list-unstyled">
                      <li>
                        <strong>Email:</strong> dpo@site-analyser.com
                      </li>
                      <li>
                        <strong>Phone:</strong> +1 (555) 123-4567
                      </li>
                      <li>
                        <strong>Office Hours:</strong> Mon-Fri 9AM-5PM EST
                      </li>
                    </ul>
                  </div>
                </div>

                <h5>Mailing Address</h5>
                <address>
                  Site-Analyser Privacy Team
                  <br />
                  123 Security Street, Suite 456
                  <br />
                  Tech City, TC 12345
                  <br />
                  United States
                </address>

                <h5>EU Representative</h5>
                <address>
                  Site-Analyser EU Privacy Representative
                  <br />
                  456 Data Protection Avenue
                  <br />
                  Dublin, Ireland
                  <br />
                  eu-privacy@site-analyser.com
                </address>

                <div className="alert alert-success">
                  <strong>🔐 Secure Contact:</strong> For sensitive privacy
                  matters, you can use our encrypted contact form or PGP key
                  (available on our security page).
                </div>
              </section>

              {/* Footer */}
              <div className="border-top pt-4 mt-5">
                <div className="row align-items-center">
                  <div className="col-lg-8">
                    <p className="text-muted mb-2">
                      This Privacy Policy is part of our commitment to
                      transparency and your privacy rights. We regularly review
                      and update our practices to ensure the highest standards
                      of data protection.
                    </p>
                    <p className="text-muted small mb-0">
                      Last updated: June 1, 2025 | Version 2.1 |
                      <button
                        className="btn btn-link btn-sm p-0 text-muted"
                        onClick={() =>
                          window.open("/legal/privacy-history", "_blank")
                        }
                      >
                        View Version History
                      </button>
                    </p>
                  </div>
                  <div className="col-lg-4 mt-3 mt-lg-0">
                    <div className="d-grid gap-2 d-md-flex justify-content-lg-end">
                      <Link
                        to="/terms-of-service"
                        className="btn btn-outline-primary"
                      >
                        View Terms of Service
                      </Link>
                      <button
                        className="btn btn-secondary"
                        onClick={() => window.print()}
                      >
                        Print Policy
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

export default PrivacyPolicy;
