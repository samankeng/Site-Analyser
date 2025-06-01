# 📁 Project Structure – Site-Analyser

This project consists of a **React.js frontend** and a **Django backend**, supported by Docker, Celery, and an extensible compliance and scanning system.

---

## 📦 Root Directory

```
site-analyser/
├── .env                      # Environment config
├── .env.dev                 # Dev-specific overrides
├── .gitignore               # Git ignore rules
├── dockerignore             # Docker ignore rules
├── docker-compose.yml       # Multi-service Docker configuration
├── manage.py                # Django entrypoint
├── package-lock.json
├── package.json
├── requirements.txt         # Python dependencies
```

---

## ⚙️ GitHub Workflows

```
.github/
└── workflows/
    ├── ci.yml               # Continuous Integration
    └── deploy.yml           # Deployment workflow
```

---

## 🧠 Backend – Django Server

```
server/
├── Dockerfile
├── accounts/
├── ai_analyzer/
│   └── ml/
│       ├── anomaly_detection/
│       ├── risk_scoring/
│       └── threat_detection/
│   └── services/
├── alerts/
├── api/
├── celery_app/
├── integrations/
│   ├── shodan_service.py
│   ├── ssl_labs_service.py
│   └── virus_total_service.py
├── reports/
├── scanner/
│   └── services/
│       ├── content_scanner.py
│       ├── cookie_scanner.py
│       ├── cors_scanner.py
│       ├── csp_scanner.py
│       ├── header_scanner.py
│       ├── pdf_report_generator.py
│       ├── port_scanner.py
│       ├── scan_service.py
│       ├── scan_types.py
│       ├── server_analyzer.py
│       ├── ssl_scanner.py
│       └── vulnerability_scanner.py
├── scripts/
│   ├── celery-entrypoint.sh
│   └── entrypoint.sh
├── site_analyser/
│   ├── settings/
│   │   ├── base.py
│   │   ├── security_compliance.py
│   │   ├── development.py
│   │   └── production.py
│   ├── asgi.py
│   ├── urls.py
│   └── wsgi.py
├── templates/
│   └── emails/
│       ├── email_verification.html
│       ├── email_verification.txt
│       ├── password_reset.html
│       └── password_reset.txt
└── compliance/
    ├── models.py
    ├── urls.py
    ├── views.py
    └── compliance_service.py
```

---

## 🖥️ Frontend – React Client

```
client/
├── Dockerfile
├── Dockerfile.dev
├── public/
│   ├── favicon.ico
│   ├── index.html
│   ├── manifest.json
│   └── robots.txt
├── src/
│   ├── assets/
│   │   ├── css/
│   │   ├── fonts/
│   │   ├── icons/
│   │   └── images/
│   │       └── hero-image.svg
│   ├── components/
│   │   ├── admin/
│   │   │   └── AdminAuthorizationPanel.jsx
│   │   ├── common/
│   │   │   ├── Footer.js
│   │   │   ├── Navbar.js
│   │   │   └── PrivateRoute.js
│   │   ├── compliance/
│   │   │   └── ComplianceAcceptance.js
│   │   ├── dashboard/
│   │   │   ├── SecurityScoreCard.js
│   │   │   ├── VulnerabilityChart.js
│   │   │   └── AnomalyDetectionDashboard.js
│   │   ├── reports/
│   │   │   ├── AiRecommendations.js
│   │   │   ├── ReportCard.js
│   │   │   ├── ReportExport.js
│   │   │   ├── ReportList.js
│   │   │   └── VulnerabilityList.js
│   │   └── security/
│   │       ├── ScanForm.js
│   │       ├── ScanHistoryTable.js
│   │       └── ScanProgress.js
│   ├── config/
│   │   └── appConfig.js
│   ├── contexts/
│   │   └── AuthContext.js
│   ├── pages/
│   │   ├── auth/
│   │   │   ├── Login.js
│   │   │   ├── Register.js
│   │   │   ├── EmailVerificationRequiredPage.js
│   │   │   ├── ForgetPassword.js
│   │   │   └── ResetPassword.js
│   │   ├── dashboard/
│   │   │   └── Dashboard.js
│   │   ├── reports/
│   │   │   ├── ReportList.js
│   │   │   └── SecurityReport.js
│   │   ├── scans/
│   │   │   ├── NewScan.js
│   │   │   └── ScanStatus.js
│   │   ├── settings/
│   │   │   └── Settings.js
│   │   ├── HomePage.js
│   │   └── NotFound.js
│   ├── services/
│   │   ├── aiService.js
│   │   ├── api.js
│   │   ├── authService.js
│   │   ├── reportService.js
│   │   ├── ScanReportService.js
│   │   ├── scanService.js
│   │   ├── virtualReportService.js
│   │   ├── anomalyServices.js
│   │   └── socialAuthService.js
│   ├── utils/
│   │   ├── storage.js
│   │   └── securityUtils.js
│   ├── App.js
│   ├── App.css
│   ├── index.css
│   ├── logo.svg
│   ├── reportWebVitals.js
│   ├── setupTests.js
│   └── index.js
├── package.json
└── README.md
```

---

## 🌐 Nginx Reverse Proxy

```
nginx/
├── Dockerfile
└── nginx.conf
```

---

## ⚙️ Celery Worker

```
celery/
└── Dockerfile
```

---

## 📄 Docs

```
docs/
├── api/
├── architecture/
└── user-guides/
```
