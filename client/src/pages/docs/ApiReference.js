// frontend/src/pages/docs/ApiReference.js

import { useState } from "react";
import { Link } from "react-router-dom";

const ApiReference = () => {
  const [activeEndpoint, setActiveEndpoint] = useState("authentication");
  const [expandedAccordion, setExpandedAccordion] = useState("authErrors");

  const endpoints = [
    { id: "authentication", title: "Authentication", icon: "🔐" },
    { id: "scans", title: "Scans", icon: "🔍" },
    { id: "reports", title: "Reports", icon: "📊" },
    { id: "compliance", title: "Compliance", icon: "✅" },
    { id: "ai-analysis", title: "AI Analysis", icon: "🤖" },
    { id: "webhooks", title: "Webhooks", icon: "🔗" },
    { id: "rate-limits", title: "Rate Limits", icon: "⏱️" },
    { id: "errors", title: "Error Codes", icon: "⚠️" },
  ];

  const CodeBlock = ({ children, language = "json" }) => (
    <pre
      className="bg-dark text-light p-3 rounded"
      style={{ overflowX: "auto", fontSize: "0.875rem" }}
    >
      <code className={`language-${language}`}>{children}</code>
    </pre>
  );

  const toggleAccordion = (accordionId) => {
    setExpandedAccordion(
      expandedAccordion === accordionId ? null : accordionId
    );
  };

  const renderContent = () => {
    switch (activeEndpoint) {
      case "authentication":
        return (
          <div>
            <h2>🔐 Authentication</h2>
            <p className="lead">
              Site-Analyser API uses API keys for authentication. All requests
              must include your API key in the Authorization header.
            </p>

            <h3>Getting Your API Key</h3>
            <ol>
              <li>Log in to your Site-Analyser dashboard</li>
              <li>Navigate to Settings → API Keys</li>
              <li>Click "Generate New API Key"</li>
              <li>Copy and securely store your API key</li>
            </ol>

            <div className="alert alert-warning">
              <strong>⚠️ Security:</strong> Keep your API key secret. Do not
              expose it in client-side code or public repositories.
            </div>

            <h3>Authentication Header</h3>
            <p>
              Include your API key in the Authorization header of all requests:
            </p>
            <CodeBlock language="bash">
              {`curl -H "Authorization: Bearer YOUR_API_KEY" \\
     -H "Content-Type: application/json" \\
     https://api.site-analyser.com/v1/scans`}
            </CodeBlock>

            <h3>API Key Types</h3>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Key Type</th>
                    <th>Permissions</th>
                    <th>Rate Limit</th>
                    <th>Scope</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Read Only</td>
                    <td>GET requests only</td>
                    <td>1000/hour</td>
                    <td>View scans and reports</td>
                  </tr>
                  <tr>
                    <td>Read/Write</td>
                    <td>All HTTP methods</td>
                    <td>500/hour</td>
                    <td>Create, update, delete</td>
                  </tr>
                  <tr>
                    <td>Admin</td>
                    <td>Full access</td>
                    <td>2000/hour</td>
                    <td>Account management</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Authentication Response</h3>
            <p>Successful authentication returns user information:</p>
            <CodeBlock>
              {`{
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "plan": "professional",
    "api_quota": {
      "requests_remaining": 450,
      "reset_time": "2025-06-04T15:00:00Z"
    }
  }
}`}
            </CodeBlock>

            <h3>Authentication Errors</h3>
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>Status Code</th>
                    <th>Error</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>401</td>
                    <td>Unauthorized</td>
                    <td>Missing or invalid API key</td>
                  </tr>
                  <tr>
                    <td>403</td>
                    <td>Forbidden</td>
                    <td>API key lacks required permissions</td>
                  </tr>
                  <tr>
                    <td>429</td>
                    <td>Too Many Requests</td>
                    <td>Rate limit exceeded</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        );

      case "scans":
        return (
          <div>
            <h2>🔍 Scans API</h2>
            <p className="lead">
              Create, manage, and retrieve security scans programmatically.
            </p>

            <h3>Create a New Scan</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>POST</strong> <code>/api/v1/scans</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-success">Auth Required</span>
              </div>
            </div>

            <h4>Request Body</h4>
            <CodeBlock>
              {`{
  "url": "https://example.com",
  "scan_type": "comprehensive",
  "options": {
    "include_subdomains": false,
    "max_depth": 3,
    "exclude_paths": ["/admin", "/private"],
    "custom_headers": {
      "User-Agent": "Site-Analyser Bot"
    }
  },
  "compliance_frameworks": ["owasp", "pci_dss"],
  "notification_webhook": "https://your-app.com/webhook"
}`}
            </CodeBlock>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "status": "queued",
  "created_at": "2025-06-04T12:00:00Z",
  "estimated_completion": "2025-06-04T12:15:00Z",
  "target_url": "https://example.com",
  "scan_type": "comprehensive"
}`}
            </CodeBlock>

            <h3>Get Scan Status</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong> <code>/api/v1/scans/{"{scan_id}"}</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "status": "completed",
  "progress": 100,
  "created_at": "2025-06-04T12:00:00Z",
  "completed_at": "2025-06-04T12:14:32Z",
  "target_url": "https://example.com",
  "scan_type": "comprehensive",
  "results_summary": {
    "vulnerabilities_found": 5,
    "security_score": 7.2,
    "risk_level": "medium",
    "critical_issues": 1,
    "high_issues": 2,
    "medium_issues": 2,
    "low_issues": 0
  }
}`}
            </CodeBlock>

            <h3>List Scans</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong> <code>/api/v1/scans</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Query Parameters</h4>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Parameter</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Default</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>page</td>
                    <td>integer</td>
                    <td>Page number for pagination</td>
                    <td>1</td>
                  </tr>
                  <tr>
                    <td>limit</td>
                    <td>integer</td>
                    <td>Number of results per page (max 100)</td>
                    <td>20</td>
                  </tr>
                  <tr>
                    <td>status</td>
                    <td>string</td>
                    <td>Filter by scan status</td>
                    <td>all</td>
                  </tr>
                  <tr>
                    <td>url</td>
                    <td>string</td>
                    <td>Filter by target URL</td>
                    <td>-</td>
                  </tr>
                  <tr>
                    <td>date_from</td>
                    <td>date</td>
                    <td>Filter scans from date (YYYY-MM-DD)</td>
                    <td>-</td>
                  </tr>
                  <tr>
                    <td>date_to</td>
                    <td>date</td>
                    <td>Filter scans to date (YYYY-MM-DD)</td>
                    <td>-</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Cancel Scan</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>DELETE</strong> <code>/api/v1/scans/{"{scan_id}"}</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-warning">Write Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "message": "Scan cancelled successfully",
  "scan_id": "scan_abc123",
  "status": "cancelled"
}`}
            </CodeBlock>

            <h3>Scan Types</h3>
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>Scan Type</th>
                    <th>Duration</th>
                    <th>Scope</th>
                    <th>Cost</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>quick</td>
                    <td>5-10 mins</td>
                    <td>Basic security checks</td>
                    <td>1 credit</td>
                  </tr>
                  <tr>
                    <td>comprehensive</td>
                    <td>15-30 mins</td>
                    <td>Full security audit</td>
                    <td>3 credits</td>
                  </tr>
                  <tr>
                    <td>custom</td>
                    <td>Variable</td>
                    <td>Selected modules only</td>
                    <td>Variable</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        );

      case "reports":
        return (
          <div>
            <h2>📊 Reports API</h2>
            <p className="lead">
              Access detailed security reports and vulnerability data.
            </p>

            <h3>Get Scan Report</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong>{" "}
                <code>/api/v1/scans/{"{scan_id}"}/report</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "report_id": "report_xyz789",
  "generated_at": "2025-06-04T12:15:00Z",
  "target_url": "https://example.com",
  "security_score": 7.2,
  "risk_level": "medium",
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "title": "Missing Security Headers",
      "severity": "high",
      "cvss_score": 7.5,
      "category": "security_headers",
      "description": "Several important security headers are missing",
      "impact": "Potential for XSS and clickjacking attacks",
      "recommendation": "Implement Content-Security-Policy, X-Frame-Options headers",
      "affected_urls": [
        "https://example.com/",
        "https://example.com/login"
      ],
      "references": [
        "https://owasp.org/www-project-secure-headers/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
      ]
    }
  ],
  "compliance_status": {
    "owasp_top_10": {
      "score": 70,
      "passed": 7,
      "failed": 3,
      "details": "Missing protections for A1, A7, A10"
    },
    "pci_dss": {
      "score": 85,
      "passed": 8,
      "failed": 2,
      "details": "Encryption and access control requirements met"
    }
  }
}`}
            </CodeBlock>

            <h3>Export Report</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong>{" "}
                <code>/api/v1/scans/{"{scan_id}"}/export</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Query Parameters</h4>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Parameter</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Options</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>format</td>
                    <td>string</td>
                    <td>Export format</td>
                    <td>pdf, csv, json, xml</td>
                  </tr>
                  <tr>
                    <td>sections</td>
                    <td>array</td>
                    <td>Report sections to include</td>
                    <td>summary, vulnerabilities, compliance</td>
                  </tr>
                  <tr>
                    <td>severity</td>
                    <td>string</td>
                    <td>Minimum severity level</td>
                    <td>low, medium, high, critical</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h4>Example Request</h4>
            <CodeBlock language="bash">
              {`curl -H "Authorization: Bearer YOUR_API_KEY" \\
     "https://api.site-analyser.com/v1/scans/scan_abc123/export?format=pdf&sections=summary,vulnerabilities"`}
            </CodeBlock>
          </div>
        );

      case "compliance":
        return (
          <div>
            <h2>✅ Compliance API</h2>
            <p className="lead">
              Access compliance assessment results and framework-specific
              reports.
            </p>

            <h3>Get Compliance Status</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong>{" "}
                <code>/api/v1/compliance/{"{scan_id}"}</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "compliance_frameworks": {
    "owasp_top_10": {
      "overall_score": 70,
      "status": "partial_compliance",
      "requirements": [
        {
          "id": "A01_2021",
          "title": "Broken Access Control",
          "status": "passed",
          "score": 100,
          "details": "No broken access control issues found"
        },
        {
          "id": "A03_2021",
          "title": "Injection",
          "status": "failed",
          "score": 0,
          "details": "Potential SQL injection vulnerabilities detected",
          "findings": ["vuln_003", "vuln_007"]
        }
      ]
    }
  },
  "generated_at": "2025-06-04T12:15:00Z"
}`}
            </CodeBlock>

            <h3>Available Frameworks</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong> <code>/api/v1/compliance/frameworks</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "frameworks": [
    {
      "id": "owasp_top_10",
      "name": "OWASP Top 10",
      "version": "2021",
      "description": "Top 10 Web Application Security Risks",
      "categories": 10,
      "available": true
    },
    {
      "id": "pci_dss",
      "name": "PCI DSS",
      "version": "4.0",
      "description": "Payment Card Industry Data Security Standard",
      "requirements": 12,
      "available": true
    },
    {
      "id": "nist_csf",
      "name": "NIST Cybersecurity Framework",
      "version": "1.1",
      "description": "Framework for improving cybersecurity",
      "functions": 5,
      "available": true
    }
  ]
}`}
            </CodeBlock>
          </div>
        );

      case "ai-analysis":
        return (
          <div>
            <h2>🤖 AI Analysis API</h2>
            <p className="lead">
              Access AI-powered security analysis, threat detection, and
              recommendations.
            </p>

            <h3>Get AI Recommendations</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong>{" "}
                <code>/api/v1/ai/recommendations/{"{scan_id}"}</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "ai_analysis": {
    "confidence_score": 0.92,
    "analysis_timestamp": "2025-06-04T12:20:00Z",
    "model_version": "v2.1.0"
  },
  "recommendations": [
    {
      "id": "rec_001",
      "priority": "high",
      "category": "security_headers",
      "title": "Implement Content Security Policy",
      "description": "Your website lacks a Content Security Policy (CSP) header, which leaves it vulnerable to XSS attacks.",
      "impact_score": 8.5,
      "implementation_difficulty": "medium",
      "estimated_time": "2-4 hours",
      "business_impact": "Reduces risk of data theft and unauthorized script execution",
      "compliance_benefits": ["OWASP A7", "PCI DSS 6.5.1"]
    }
  ]
}`}
            </CodeBlock>

            <h3>Risk Scoring</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>GET</strong>{" "}
                <code>/api/v1/ai/risk-score/{"{scan_id}"}</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-info">Read Permission</span>
              </div>
            </div>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "scan_id": "scan_abc123",
  "overall_risk_score": 7.2,
  "risk_level": "medium",
  "score_breakdown": {
    "vulnerability_score": 6.8,
    "configuration_score": 7.5,
    "compliance_score": 7.0,
    "threat_intelligence_score": 7.6
  },
  "ai_insights": {
    "trend_analysis": "Risk score increased by 0.3 points since last scan",
    "peer_comparison": "15% higher risk than similar websites",
    "improvement_potential": "Score could improve to 4.2 by addressing top 3 issues"
  }
}`}
            </CodeBlock>
          </div>
        );

      case "webhooks":
        return (
          <div>
            <h2>🔗 Webhooks</h2>
            <p className="lead">
              Configure webhooks to receive real-time notifications about scan
              events and security findings.
            </p>

            <h3>Webhook Events</h3>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Description</th>
                    <th>Frequency</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>scan.started</td>
                    <td>Scan has been queued and started</td>
                    <td>Per scan</td>
                  </tr>
                  <tr>
                    <td>scan.completed</td>
                    <td>Scan finished successfully</td>
                    <td>Per scan</td>
                  </tr>
                  <tr>
                    <td>scan.failed</td>
                    <td>Scan encountered an error</td>
                    <td>Per scan</td>
                  </tr>
                  <tr>
                    <td>vulnerability.critical</td>
                    <td>Critical vulnerability discovered</td>
                    <td>Per finding</td>
                  </tr>
                  <tr>
                    <td>compliance.failed</td>
                    <td>Compliance check failed</td>
                    <td>Per framework</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Configure Webhook</h3>
            <div className="row">
              <div className="col-md-6">
                <strong>POST</strong> <code>/api/v1/webhooks</code>
              </div>
              <div className="col-md-6 text-end">
                <span className="badge bg-warning">Write Permission</span>
              </div>
            </div>

            <h4>Request Body</h4>
            <CodeBlock>
              {`{
  "url": "https://your-app.com/webhook/site-analyser",
  "events": [
    "scan.completed",
    "vulnerability.critical"
  ],
  "secret": "your-webhook-secret",
  "active": true,
  "filters": {
    "min_severity": "high",
    "domains": ["example.com", "test.example.com"]
  }
}`}
            </CodeBlock>

            <h4>Response</h4>
            <CodeBlock>
              {`{
  "webhook_id": "webhook_123",
  "url": "https://your-app.com/webhook/site-analyser",
  "events": ["scan.completed", "vulnerability.critical"],
  "created_at": "2025-06-04T12:00:00Z",
  "status": "active"
}`}
            </CodeBlock>

            <h3>Webhook Payload Example</h3>
            <h4>Scan Completed Event</h4>
            <CodeBlock>
              {`{
  "event": "scan.completed",
  "timestamp": "2025-06-04T12:15:00Z",
  "webhook_id": "webhook_123",
  "data": {
    "scan_id": "scan_abc123",
    "target_url": "https://example.com",
    "status": "completed",
    "security_score": 7.2,
    "vulnerabilities_found": 5,
    "critical_issues": 1,
    "scan_duration": 874,
    "report_url": "https://api.site-analyser.com/v1/scans/scan_abc123/report"
  }
}`}
            </CodeBlock>

            <h3>Webhook Security</h3>
            <p>
              All webhook payloads are signed using HMAC-SHA256. Verify the
              signature using the webhook secret:
            </p>

            <CodeBlock language="python">
              {`import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(
        f"sha256={expected_signature}",
        signature
    )`}
            </CodeBlock>
          </div>
        );

      case "rate-limits":
        return (
          <div>
            <h2>⏱️ Rate Limits</h2>
            <p className="lead">
              Understanding API rate limits and how to handle them effectively.
            </p>

            <h3>Rate Limit Tiers</h3>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Plan</th>
                    <th>Requests/Hour</th>
                    <th>Scans/Month</th>
                    <th>Burst Limit</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Free</td>
                    <td>100</td>
                    <td>10</td>
                    <td>20/minute</td>
                  </tr>
                  <tr>
                    <td>Professional</td>
                    <td>1,000</td>
                    <td>100</td>
                    <td>100/minute</td>
                  </tr>
                  <tr>
                    <td>Enterprise</td>
                    <td>10,000</td>
                    <td>1,000</td>
                    <td>500/minute</td>
                  </tr>
                  <tr>
                    <td>Custom</td>
                    <td>Negotiable</td>
                    <td>Negotiable</td>
                    <td>Negotiable</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Rate Limit Headers</h3>
            <p>
              Every API response includes rate limit information in the headers:
            </p>
            <CodeBlock language="bash">
              {`HTTP/1.1 200 OK
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1623456000
X-RateLimit-Burst-Limit: 100
X-RateLimit-Burst-Remaining: 99`}
            </CodeBlock>

            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>Header</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>X-RateLimit-Limit</td>
                    <td>Total requests allowed per hour</td>
                  </tr>
                  <tr>
                    <td>X-RateLimit-Remaining</td>
                    <td>Requests remaining in current window</td>
                  </tr>
                  <tr>
                    <td>X-RateLimit-Reset</td>
                    <td>Unix timestamp when limits reset</td>
                  </tr>
                  <tr>
                    <td>X-RateLimit-Burst-Limit</td>
                    <td>Maximum burst requests per minute</td>
                  </tr>
                  <tr>
                    <td>X-RateLimit-Burst-Remaining</td>
                    <td>Burst requests remaining</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Rate Limit Exceeded Response</h3>
            <p>
              When rate limits are exceeded, the API returns a 429 status code:
            </p>
            <CodeBlock>
              {`HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1623456000
Retry-After: 3600

{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "API rate limit exceeded",
    "details": {
      "limit": 1000,
      "window": "1 hour",
      "reset_time": "2025-06-04T13:00:00Z"
    }
  }
}`}
            </CodeBlock>

            <h3>Best Practices</h3>
            <div className="row">
              <div className="col-md-6">
                <h4>Handling Rate Limits</h4>
                <ul>
                  <li>Monitor rate limit headers in responses</li>
                  <li>Implement exponential backoff for retries</li>
                  <li>Respect the Retry-After header</li>
                  <li>Cache responses when possible</li>
                  <li>Batch operations when available</li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>Optimizing Usage</h4>
                <ul>
                  <li>Use pagination for large datasets</li>
                  <li>Filter requests to reduce API calls</li>
                  <li>Use webhooks instead of polling</li>
                  <li>Implement client-side caching</li>
                  <li>Consider upgrading plan if needed</li>
                </ul>
              </div>
            </div>

            <h3>Example: Rate Limit Handling</h3>
            <CodeBlock language="python">
              {`import time
import requests

def api_request_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"Rate limited. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
        else:
            response.raise_for_status()
    
    raise Exception("Max retries exceeded")`}
            </CodeBlock>
          </div>
        );

      case "errors":
        return (
          <div>
            <h2>⚠️ Error Codes</h2>
            <p className="lead">
              Complete reference for API error codes and troubleshooting
              guidance.
            </p>

            <h3>HTTP Status Codes</h3>
            <div className="table-responsive">
              <table className="table table-striped">
                <thead>
                  <tr>
                    <th>Status Code</th>
                    <th>Meaning</th>
                    <th>Common Causes</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>200</td>
                    <td>OK</td>
                    <td>Request successful</td>
                  </tr>
                  <tr>
                    <td>201</td>
                    <td>Created</td>
                    <td>Resource created successfully</td>
                  </tr>
                  <tr>
                    <td>400</td>
                    <td>Bad Request</td>
                    <td>Invalid request format or parameters</td>
                  </tr>
                  <tr>
                    <td>401</td>
                    <td>Unauthorized</td>
                    <td>Missing or invalid API key</td>
                  </tr>
                  <tr>
                    <td>403</td>
                    <td>Forbidden</td>
                    <td>Insufficient permissions</td>
                  </tr>
                  <tr>
                    <td>404</td>
                    <td>Not Found</td>
                    <td>Resource doesn't exist</td>
                  </tr>
                  <tr>
                    <td>429</td>
                    <td>Too Many Requests</td>
                    <td>Rate limit exceeded</td>
                  </tr>
                  <tr>
                    <td>500</td>
                    <td>Internal Server Error</td>
                    <td>Server-side error</td>
                  </tr>
                  <tr>
                    <td>503</td>
                    <td>Service Unavailable</td>
                    <td>Temporary service outage</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <h3>Error Response Format</h3>
            <p>All error responses follow a consistent format:</p>
            <CodeBlock>
              {`{
  "error": {
    "code": "validation_error",
    "message": "Invalid request parameters",
    "details": {
      "field": "url",
      "issue": "Invalid URL format",
      "provided_value": "not-a-url"
    },
    "request_id": "req_12345",
    "timestamp": "2025-06-04T12:00:00Z"
  }
}`}
            </CodeBlock>

            <h3>Common Error Codes</h3>

            {/* Manual Accordion Implementation */}
            <div className="mb-3">
              <div className="card">
                <div className="card-header">
                  <button
                    className="btn btn-link text-start w-100 text-decoration-none d-flex justify-content-between align-items-center"
                    type="button"
                    onClick={() => toggleAccordion("authErrors")}
                  >
                    <span>🔐 Authentication Errors</span>
                    <span>
                      {expandedAccordion === "authErrors" ? "−" : "+"}
                    </span>
                  </button>
                </div>
                {expandedAccordion === "authErrors" && (
                  <div className="card-body">
                    <div className="table-responsive">
                      <table className="table table-sm">
                        <thead>
                          <tr>
                            <th>Code</th>
                            <th>Message</th>
                            <th>Solution</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td>invalid_api_key</td>
                            <td>API key is invalid or expired</td>
                            <td>
                              Check API key format and regenerate if needed
                            </td>
                          </tr>
                          <tr>
                            <td>missing_authorization</td>
                            <td>Authorization header missing</td>
                            <td>
                              Include Authorization header with Bearer token
                            </td>
                          </tr>
                          <tr>
                            <td>insufficient_permissions</td>
                            <td>API key lacks required permissions</td>
                            <td>Upgrade API key permissions or plan</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="mb-3">
              <div className="card">
                <div className="card-header">
                  <button
                    className="btn btn-link text-start w-100 text-decoration-none d-flex justify-content-between align-items-center"
                    type="button"
                    onClick={() => toggleAccordion("validationErrors")}
                  >
                    <span>✏️ Validation Errors</span>
                    <span>
                      {expandedAccordion === "validationErrors" ? "−" : "+"}
                    </span>
                  </button>
                </div>
                {expandedAccordion === "validationErrors" && (
                  <div className="card-body">
                    <div className="table-responsive">
                      <table className="table table-sm">
                        <thead>
                          <tr>
                            <th>Code</th>
                            <th>Message</th>
                            <th>Solution</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td>invalid_url</td>
                            <td>URL format is invalid</td>
                            <td>Provide valid URL with protocol (https://)</td>
                          </tr>
                          <tr>
                            <td>missing_required_field</td>
                            <td>Required parameter missing</td>
                            <td>Include all required fields in request</td>
                          </tr>
                          <tr>
                            <td>invalid_scan_type</td>
                            <td>Scan type not supported</td>
                            <td>Use: quick, comprehensive, or custom</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="mb-3">
              <div className="card">
                <div className="card-header">
                  <button
                    className="btn btn-link text-start w-100 text-decoration-none d-flex justify-content-between align-items-center"
                    type="button"
                    onClick={() => toggleAccordion("scanErrors")}
                  >
                    <span>🔍 Scan Errors</span>
                    <span>
                      {expandedAccordion === "scanErrors" ? "−" : "+"}
                    </span>
                  </button>
                </div>
                {expandedAccordion === "scanErrors" && (
                  <div className="card-body">
                    <div className="table-responsive">
                      <table className="table table-sm">
                        <thead>
                          <tr>
                            <th>Code</th>
                            <th>Message</th>
                            <th>Solution</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td>scan_not_found</td>
                            <td>Scan ID does not exist</td>
                            <td>Verify scan ID and permissions</td>
                          </tr>
                          <tr>
                            <td>scan_still_running</td>
                            <td>Scan is currently in progress</td>
                            <td>
                              Wait for scan completion before accessing results
                            </td>
                          </tr>
                          <tr>
                            <td>target_unreachable</td>
                            <td>Cannot connect to target URL</td>
                            <td>Verify URL accessibility and DNS resolution</td>
                          </tr>
                          <tr>
                            <td>scan_quota_exceeded</td>
                            <td>Monthly scan limit reached</td>
                            <td>Upgrade plan or wait for quota reset</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <h3>Error Handling Best Practices</h3>
            <div className="row">
              <div className="col-md-6">
                <h4>Client Implementation</h4>
                <ul>
                  <li>Always check HTTP status codes</li>
                  <li>Parse error responses for details</li>
                  <li>Implement retry logic for 5xx errors</li>
                  <li>Log request_id for support cases</li>
                  <li>Handle rate limits gracefully</li>
                </ul>
              </div>
              <div className="col-md-6">
                <h4>Error Recovery</h4>
                <ul>
                  <li>Validate inputs before sending requests</li>
                  <li>Implement exponential backoff</li>
                  <li>Use circuit breaker pattern</li>
                  <li>Provide meaningful user feedback</li>
                  <li>Monitor error rates and patterns</li>
                </ul>
              </div>
            </div>

            <h3>Example Error Handler</h3>
            <CodeBlock language="javascript">
              {`async function handleApiRequest(url, options) {
  try {
    const response = await fetch(url, options);
    
    if (!response.ok) {
      const errorData = await response.json();
      
      switch (response.status) {
        case 401:
          throw new Error('Authentication failed. Check API key.');
        case 403:
          throw new Error('Insufficient permissions.');
        case 429:
          const retryAfter = response.headers.get('Retry-After');
          throw new Error(\`Rate limited. Retry after \${retryAfter} seconds.\`);
        case 500:
        case 502:
        case 503:
          throw new Error('Server error. Please try again later.');
        default:
          throw new Error(errorData.error.message || 'Unknown error occurred');
      }
    }
    
    return await response.json();
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
}`}
            </CodeBlock>

            <h3>Getting Support</h3>
            <p>When contacting support about API errors, please include:</p>
            <ul>
              <li>Request ID from error response</li>
              <li>Full error message and code</li>
              <li>Timestamp of the request</li>
              <li>Request details (method, endpoint, parameters)</li>
              <li>Your API key (last 4 characters only)</li>
            </ul>

            <div className="alert alert-info">
              <strong>📧 Support:</strong> Email api-support@site-analyser.com
              with error details for faster resolution.
            </div>
          </div>
        );

      default:
        return (
          <div className="text-center py-5">
            <div className="mb-4">
              <h3>Select an endpoint from the sidebar</h3>
              <p className="text-muted">
                Choose a section from the left to view detailed API
                documentation.
              </p>
            </div>
            <div className="row justify-content-center">
              <div className="col-md-8">
                <div className="card bg-light">
                  <div className="card-body">
                    <h5 className="card-title">🚀 Getting Started</h5>
                    <p className="card-text">
                      Welcome to the Site-Analyser API! Start with the
                      Authentication section to learn how to get your API key
                      and make your first request.
                    </p>
                    <button
                      className="btn btn-primary"
                      onClick={() => setActiveEndpoint("authentication")}
                    >
                      View Authentication Guide
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="container-fluid py-4">
      <div className="row">
        {/* Sidebar */}
        <div className="col-lg-3 col-md-4">
          <div className="card sticky-top" style={{ top: "20px" }}>
            <div className="card-header bg-primary text-white">
              <h5 className="mb-0">🔧 API Reference</h5>
            </div>
            <div className="list-group list-group-flush">
              {endpoints.map((endpoint) => (
                <button
                  key={endpoint.id}
                  className={`list-group-item list-group-item-action d-flex align-items-center ${
                    activeEndpoint === endpoint.id ? "active" : ""
                  }`}
                  onClick={() => setActiveEndpoint(endpoint.id)}
                >
                  <span className="me-2">{endpoint.icon}</span>
                  <span>{endpoint.title}</span>
                </button>
              ))}
            </div>
          </div>

          {/* API Status */}
          <div className="card mt-3">
            <div className="card-header">
              <h6 className="mb-0">📊 API Status</h6>
            </div>
            <div className="card-body">
              <div className="d-flex align-items-center mb-2">
                <span className="badge bg-success me-2">●</span>
                <small>All systems operational</small>
              </div>
              <div className="d-flex align-items-center mb-2">
                <small>
                  <strong>API Version:</strong> v1.2.0
                </small>
              </div>
              <div className="d-flex align-items-center">
                <small>
                  <strong>Uptime:</strong> 99.9%
                </small>
              </div>
            </div>
          </div>

          {/* Quick Links */}
          <div className="card mt-3">
            <div className="card-header">
              <h6 className="mb-0">🔗 Quick Links</h6>
            </div>
            <div className="card-body">
              <div className="d-grid gap-2">
                <Link to="/settings" className="btn btn-outline-primary btn-sm">
                  Manage API Keys
                </Link>
                <button className="btn btn-outline-success btn-sm">
                  Test API
                </button>
                <button className="btn btn-outline-info btn-sm">
                  Postman Collection
                </button>
                <button className="btn btn-outline-secondary btn-sm">
                  SDK Downloads
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="col-lg-9 col-md-8">
          <div className="card">
            <div className="card-body p-4">{renderContent()}</div>
          </div>

          {/* Base URL Info */}
          <div className="card mt-4">
            <div className="card-body">
              <h5>🌐 Base URL</h5>
              <p>All API requests should be made to:</p>
              <div className="bg-light p-3 rounded">
                <code>https://api.site-analyser.com/v1</code>
              </div>

              <h5 className="mt-4">📚 SDKs & Libraries</h5>
              <div className="row">
                <div className="col-md-3 col-sm-6 mb-2">
                  <strong>Python</strong>
                  <br />
                  <code className="small">pip install site-analyser-sdk</code>
                </div>
                <div className="col-md-3 col-sm-6 mb-2">
                  <strong>Node.js</strong>
                  <br />
                  <code className="small">npm install site-analyser</code>
                </div>
                <div className="col-md-3 col-sm-6 mb-2">
                  <strong>PHP</strong>
                  <br />
                  <code className="small">
                    composer require site-analyser/api
                  </code>
                </div>
                <div className="col-md-3 col-sm-6 mb-2">
                  <strong>Ruby</strong>
                  <br />
                  <code className="small">gem install site_analyser</code>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ApiReference;
