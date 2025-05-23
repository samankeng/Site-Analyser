# Site-Analyser: React Frontend + Django Backend

## Project Directory Structure

```
site-analyser/
├── .github/                     # GitHub configuration
│   └── workflows/              # GitHub Actions workflows
│       ├── ci.yml              # CI workflow
│       └── deploy.yml          # Deployment workflow
├── client/                     # React Frontend
│   ├── public/                 # Static assets
│   │   ├── favicon.ico
│   │   ├── index.html
│   │   ├── manifest.json
│   │   └── robots.txt
│   └── src/
│       ├── assets/             # Static files (images, fonts, etc.)
│       │   ├── css/
│       │   ├── fonts/
│       │   ├── icons/
│       │   └── images/
│       │       └── hero-image.svg
│       ├── components/         # Reusable UI components
│       │   ├── common/         # Shared components
│       │   │   ├── Footer.js
│       │   │   ├── Navbar.js
│       │   │   └── PrivateRoute.js
│       │   ├── dashboard/      # Dashboard-specific components
│       │   │   ├── SecurityScoreCard.js
│       │   │   └── VulnerabilityChart.js
│       │   ├── reports/        # Report-specific components
│       │   │   ├── AiRecommendations.js
│       │   │   ├── ReportCard.js
│       │   │   ├── ReportExport.js
│       │   │   ├── ReportList.js
│       │   │   └── VulnerabilityList.js
│       │   └── security/       # Security analysis components
│       │       ├── ScanForm.js
│       │       ├── ScanHistoryTable.js
│       │       └── ScanProgress.js
│       ├── contexts/          # React context providers
│       │   └── AuthContext.js
│       ├── hooks/             # Custom React hooks
│       ├── pages/             # Page components
│       │   ├── auth/
│       │   │   ├── Login.js
│       │   │   └── Register.js
│       │   ├── dashboard/
│       │   │   └── Dashboard.js
│       │   ├── reports/
│       │   │   ├── ReportList.js
│       │   │   └── SecurityReport.js
│       │   ├── scans/
│       │   │   ├── NewScan.js
│       │   │   └── ScanStatus.js
│       │   ├── settings/
│       │   │   └── Settings.js
│       │   ├── HomePage.js
│       │   └── NotFound.js
│       ├── services/          # API service integrations
│       │   ├── aiService.js
│       │   ├── api.js
│       │   ├── authService.js
│       │   ├── reportService.js
│       │   ├── ScanReportService.js
│       │   ├── scanService.js
│       │   └── virtualReportService.js
│       ├── store/             # Redux state management
│       ├── utils/             # Utility functions
│       │   └── storage.js
│       ├── App.js             # Main application component
│       ├── App.css
│       ├── index.css
│       ├── logo.svg
│       ├── reportWebVitals.js
│       ├── setupTests.js
│       ├── index.js           # Entry point
│       ├── routes.js          # Application routes
│       └── theme.js           # UI theme configuration
├── docker/                     # Docker configuration
│   ├── celery/
│   │   └── Dockerfile
│   ├── client/
│   │   ├── Dockerfile
│   │   ├── Dockerfile.dev
│   │   └── nginx.conf
│   ├── nginx/
│   │   ├── Dockerfile
│   │   └── nginx.conf
│   ├── scripts/
│   │   ├── celery-entrypoint.sh
│   │   └── entrypoint.sh
│   └── server/
│       └── Dockerfile
├── docs/                       # Documentation
│   ├── api/
│   ├── architecture/
│   └── user-guides/
├── server/                     # Django Backend
│   ├── accounts/              # User accounts management
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── serializers.py
│   │   ├── urls.py
│   │   └── views.py
│   ├── ai_analyzer/           # AI analysis module
│   │   ├── ml/
│   │   │   ├── anomaly_detection/
│   │   │   │   └── model.py
│   │   │   ├── risk_scoring/
│   │   │   │   └── model.py
│   │   │   └── threat_detection/
│   │   │       └── model.py
│   │   ├── services/
│   │   │   ├── ai_analysis.py
│   │   │   ├── ollama_client.py
│   │   │   ├── threat_intelligence.py
│   │   │   └── __init__.py
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── serializers.py
│   │   ├── urls.py
│   │   └── views.py
│   ├── alerts/                # Alert system
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   └── views.py
│   ├── api/                   # API configuration
│   │   ├── __init__.py
│   │   ├── apps.py
│   │   └── urls.py
│   ├── celery_app/            # Celery task queue
│   │   ├── __init__.py
│   │   ├── celery.py
│   │   └── tasks.py
│   ├── integrations/          # External service integrations
│   │   ├── __init__.py
│   │   ├── shodan_service.py
│   │   ├── ssl_labs_service.py
│   │   └── virus_total_service.py
│   ├── reports/               # Report generation
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── serializers.py
│   │   ├── urls.py
│   │   └── views.py
│   ├── scanner/               # Security scanning services
│   │   ├── services/
│   │   │   ├── content_scanner.py
│   │   │   ├── cookie_scanner.py
│   │   │   ├── cors_scanner.py
│   │   │   ├── csp_scanner.py
│   │   │   ├── header_scanner.py
│   │   │   ├── pdf_report_generator.py
│   │   │   ├── port_scanner.py
│   │   │   ├── scan_service.py
│   │   │   ├── scan_types.py
│   │   │   ├── server_analyzer.py
│   │   │   ├── ssl_scanner.py
│   │   │   └── vulnerability_scanner.py
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── serializers.py
│   │   ├── urls.py
│   │   └── views.py
│   ├── scripts/               # Server scripts
│   │   ├── celery-entrypoint.sh
│   │   └── entrypoint.sh
│   ├── site_analyser/         # Django project settings
│   │   ├── settings/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── development.py
│   │   │   └── production.py
│   │   ├── __init__.py
│   │   ├── asgi.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   ├── .env                   # Environment variables
│   ├── manage.py
│   └── requirements.txt
├── .gitignore
├── .dockerignore
├── docker-compose.yml
├── package-lock.json
└── package.json
```

## Architecture Overview

This project is a full-stack web application combining:

- **Frontend**: React-based SPA for the user interface
- **Backend**: Django REST framework for API services
- **Task Queue**: Celery for asynchronous processing
- **Data Analysis**: AI/ML modules for security analysis
- **Containerization**: Docker for consistent deployment

### Key Components

1. **Frontend (React)**
   - Modular component architecture
   - Client-side routing and state management
   - Service layer for API communication

2. **Backend (Django)**
   - RESTful API endpoints
   - Modular app structure for different functionalities
   - Async task processing with Celery

3. **Security Features**
   - Multiple scanning services
   - AI-powered threat detection
   - Third-party security integrations
   - PDF report generation

4. **DevOps**
   - Dockerized development and deployment
   - CI/CD workflows with GitHub Actions
   - Environment-specific configurations
