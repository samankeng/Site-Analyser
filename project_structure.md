# Site-Analyser Project Structure

## Overview
Site-Analyser is a comprehensive web security analysis platform built with React frontend and Django backend, featuring AI-powered security analysis, anomaly detection, and automated reporting.

## 📁 Root Directory Structure

```
site-analyser/
├── .github/                    # GitHub configuration
│   └── workflows/              # CI/CD workflows
│       ├── ci.yml             # Continuous Integration
│       └── deploy.yml         # Deployment pipeline
├── client/                     # React Frontend Application
├── server/                     # Django Backend Application
├── docker/                     # Docker configurations
├── docs/                       # Project documentation
├── .gitignore                 # Git ignore rules
├── .dockerignore              # Docker ignore rules
├── docker-compose.yml         # Multi-container setup
├── package.json               # Root package configuration
└── package-lock.json          # Dependency lock file
```

## 🎯 Frontend Structure (`client/`)

### Public Assets
```
client/public/
├── favicon.ico                # Site favicon
├── index.html                 # HTML template
├── manifest.json              # Progressive Web App manifest
└── robots.txt                 # Search engine directives
```

### Source Code Structure
```
client/src/
├── assets/                    # Static assets
│   ├── css/                   # Stylesheets
│   ├── fonts/                 # Custom fonts
│   ├── icons/                 # Icon files
│   └── images/                # Images and graphics
│       └── hero-image.svg     # Main hero image
├── components/                # Reusable React components
├── contexts/                  # React Context providers
├── pages/                     # Page-level components
├── services/                  # API service layer
├── utils/                     # Utility functions
├── config/                    # Configuration files
├── App.js                     # Main application component
├── App.css                    # Main application styles
├── index.js                   # Application entry point
├── index.css                  # Global styles
└── setupTests.js              # Test configuration
```

### Component Architecture
```
components/
├── common/                    # Shared components
│   ├── Footer.js              # Site footer
│   ├── Navbar.js              # Navigation bar
│   └── PrivateRoute.js        # Route protection
├── dashboard/                 # Dashboard-specific components
│   ├── SecurityScoreCard.js   # Security score display
│   ├── VulnerabilityChart.js  # Vulnerability visualization
│   └── AnomalyDetectionDashboard.js # AI anomaly detection
├── reports/                   # Report-related components
│   ├── AiRecommendations.js   # AI-generated recommendations
│   ├── ReportCard.js          # Report summary card
│   ├── ReportExport.js        # Export functionality
│   ├── ReportList.js          # Report listing
│   └── VulnerabilityList.js   # Vulnerability details
├── security/                  # Security analysis components
│   ├── ScanForm.js            # Scan creation form
│   ├── ScanHistoryTable.js    # Scan history display
│   └── ScanProgress.js        # Scan progress indicator
├── auth/                      # Authentication components
│   ├── EmailVerification.js   # Email verification
│   ├── EmailVerificationRequired.js # Verification prompt
│   ├── GitHubCallback.js      # GitHub OAuth callback
│   ├── MicrosoftCallback.js   # Microsoft OAuth callback
│   └── SocialLoginButtons.js  # Social login UI
└── settings/                  # Settings components
    └── SocialAccountsSettings.js # Social account management
```

### Page Structure
```
pages/
├── auth/                      # Authentication pages
│   ├── Login.js               # User login
│   ├── Register.js            # User registration
│   ├── EmailVerificationRequiredPage.js # Email verification
│   ├── ForgetPassword.js      # Password reset request
│   └── ResetPassword.js       # Password reset form
├── dashboard/                 # Dashboard pages
│   └── Dashboard.js           # Main dashboard
├── reports/                   # Report pages
│   ├── ReportList.js          # Report listing page
│   └── SecurityReport.js      # Individual report view
├── scans/                     # Scan management pages
│   ├── NewScan.js             # Create new scan
│   └── ScanStatus.js          # Scan status tracking
├── settings/                  # Settings pages
│   └── Settings.js            # User settings
├── HomePage.js                # Landing page
└── NotFound.js                # 404 error page
```

### Service Layer
```
services/
├── __tests__/                 # Service tests
│   ├── aiService.test.js      # AI service tests
│   ├── anomalyServices.test.js # Anomaly detection tests
│   ├── api.test.js            # API client tests
│   ├── authService.test.js    # Authentication tests
│   ├── reportService.test.js  # Report service tests
│   ├── scanReportService.test.js # Scan report tests
│   ├── scanService.test.js    # Scan service tests
│   ├── socialAuthService.test.js # Social auth tests
│   └── virtualReportService.test.js # Virtual report tests
├── aiService.js               # AI analysis integration
├── anomalyServices.js         # Anomaly detection
├── api.js                     # HTTP client configuration
├── authService.js             # Authentication service
├── reportService.js           # Report management
├── scanReportService.js       # Scan report handling
├── scanService.js             # Security scanning
├── socialAuthService.js       # Social authentication
└── virtualReportService.js    # Virtual report generation
```

### Utilities and Configuration
```
utils/
├── storage.js                 # Local storage utilities
└── securityUtils.js           # Security-related utilities

contexts/
└── AuthContext.js             # Authentication context

config/
└── appConfig.js               # Application configuration
```

## 🔧 Backend Structure (`server/`)

### Django Applications
```
server/
├── accounts/                  # User account management
│   ├── __init__.py
│   ├── admin.py               # Admin interface configuration
│   ├── apps.py                # App configuration
│   ├── models.py              # User models
│   ├── serializers.py         # API serializers
│   ├── urls.py                # URL routing
│   ├── views.py               # API views
│   └── pipeline.py            # Social auth pipeline
├── ai_analyzer/               # AI-powered analysis
│   ├── ml/                    # Machine learning models
│   │   ├── anomaly_detection/ # Anomaly detection
│   │   ├── risk_scoring/      # Risk assessment
│   │   └── threat_detection/  # Threat identification
│   ├── services/              # AI services
│   │   ├── __init__.py
│   │   ├── ai_analysis.py     # Core AI analysis
│   │   ├── llm_service.py     # Language model integration
│   │   ├── ollama_client.py   # Ollama client
│   │   ├── openai_client.py   # OpenAI integration
│   │   └── threat_intelligence.py # Threat data
│   ├── models.py              # AI analysis models
│   ├── serializers.py         # API serializers
│   ├── urls.py                # URL routing
│   ├── views.py               # API views
│   └── admin.py               # Admin configuration
├── alerts/                    # Alert system
│   ├── __init__.py
│   ├── admin.py               # Alert admin interface
│   ├── apps.py                # App configuration
│   ├── models.py              # Alert models
│   └── views.py               # Alert views
├── api/                       # Core API functionality
│   ├── __init__.py
│   ├── apps.py                # API app configuration
│   ├── urls.py                # API URL routing
│   └── views.py               # Core API views
├── celery_app/                # Celery task queue
│   ├── __init__.py
│   ├── celery.py              # Celery configuration
│   └── tasks.py               # Background tasks
├── integrations/              # External service integrations
│   ├── __init__.py
│   ├── shodan_service.py      # Shodan API integration
│   ├── ssl_labs_service.py    # SSL Labs integration
│   └── virus_total_service.py # VirusTotal integration
├── reports/                   # Report management
│   ├── __init__.py
│   ├── admin.py               # Report admin interface
│   ├── apps.py                # App configuration
│   ├── models.py              # Report models
│   ├── serializers.py         # Report serializers
│   ├── urls.py                # Report URL routing
│   └── views.py               # Report views
├── scanner/                   # Security scanning engine
│   ├── services/              # Scanning services
│   │   ├── content_scanner.py # Content analysis
│   │   ├── cookie_scanner.py  # Cookie security analysis
│   │   ├── cors_scanner.py    # CORS configuration check
│   │   ├── csp_scanner.py     # Content Security Policy
│   │   ├── header_scanner.py  # HTTP header analysis
│   │   ├── pdf_report_generator.py # PDF report creation
│   │   ├── port_scanner.py    # Port scanning
│   │   ├── scan_service.py    # Core scanning logic
│   │   ├── scan_types.py      # Scan type definitions
│   │   ├── server_analyzer.py # Server analysis
│   │   ├── ssl_scanner.py     # SSL/TLS analysis
│   │   └── vulnerability_scanner.py # Vulnerability detection
│   ├── __init__.py
│   ├── admin.py               # Scanner admin interface
│   ├── apps.py                # App configuration
│   ├── models.py              # Scan models
│   ├── serializers.py         # Scan serializers
│   ├── urls.py                # Scanner URL routing
│   └── views.py               # Scanner views
├── scripts/                   # Deployment scripts
│   ├── celery-entrypoint.sh   # Celery startup script
│   └── entrypoint.sh          # Main startup script
├── site_analyser/             # Django project configuration
│   ├── settings/              # Environment-specific settings
│   │   ├── __init__.py
│   │   ├── base.py            # Base settings
│   │   ├── development.py     # Development settings
│   │   └── production.py      # Production settings
│   ├── __init__.py
│   ├── asgi.py                # ASGI configuration
│   ├── urls.py                # Main URL configuration
│   └── wsgi.py                # WSGI configuration
├── templates/                 # Email templates
│   └── emails/                # Email templates
│       ├── email_verification.html # Email verification HTML
│       ├── email_verification.txt  # Email verification text
│       ├── password_reset.html     # Password reset HTML
│       └── password_reset.txt      # Password reset text
├── .env                       # Environment variables
├── manage.py                  # Django management script
└── requirements.txt           # Python dependencies
```

## 🐳 Docker Structure (`docker/`)

```
docker/
├── celery/                    # Celery worker container
│   └── Dockerfile             # Celery Docker configuration
├── client/                    # Frontend container
│   ├── Dockerfile             # Production build
│   ├── Dockerfile.dev         # Development build
│   └── nginx.conf             # Nginx configuration
├── nginx/                     # Nginx reverse proxy
│   ├── Dockerfile             # Nginx container
│   └── nginx.conf             # Main Nginx config
└── server/                    # Backend container
    └── Dockerfile             # Django Docker configuration
```

## 📚 Documentation Structure (`docs/`)

```
docs/
├── api/                       # API documentation
├── architecture/              # System architecture docs
└── user-guides/               # User documentation
```

## 🔧 Technology Stack

### Frontend Technologies
- **React 18+** - Modern React with hooks and functional components
- **React Router** - Client-side routing
- **Bootstrap 5** - UI framework and responsive design
- **Axios** - HTTP client for API communication
- **Chart.js/Recharts** - Data visualization
- **Jest & React Testing Library** - Testing framework

### Backend Technologies
- **Django 4+** - Python web framework
- **Django REST Framework** - API development
- **Celery** - Asynchronous task processing
- **Redis** - Message broker and caching
- **PostgreSQL** - Primary database
- **JWT Authentication** - Token-based authentication
- **Social Auth** - OAuth integration (GitHub, Microsoft)

### AI/ML Technologies
- **OpenAI API** - Language model integration
- **Ollama** - Local language model support
- **Scikit-learn** - Machine learning algorithms
- **TensorFlow/PyTorch** - Deep learning (anomaly detection)

### Security Tools Integration
- **SSL Labs API** - SSL/TLS analysis
- **Shodan API** - Internet-connected device scanning
- **VirusTotal API** - Malware detection
- **Custom scanners** - Headers, ports, vulnerabilities

### DevOps & Deployment
- **Docker & Docker Compose** - Containerization
- **GitHub Actions** - CI/CD pipeline
- **Nginx** - Web server and reverse proxy
- **Gunicorn** - WSGI HTTP server

## 🧪 Testing Strategy

### Frontend Testing
```
client/src/services/__tests__/
├── aiService.test.js          # AI service functionality
├── anomalyServices.test.js    # Anomaly detection
├── api.test.js                # HTTP client
├── authService.test.js        # Authentication
├── reportService.test.js      # Report management
├── scanReportService.test.js  # Scan reports
├── scanService.test.js        # Security scanning
├── socialAuthService.test.js  # Social authentication
└── virtualReportService.test.js # Virtual reports

client/src/components/__tests__/
├── security/
│   └── ScanForm.test.js       # Scan form component
└── ... (additional component tests)
```

### Test Coverage Areas
- **Unit Tests** - Individual functions and components
- **Integration Tests** - API service interactions
- **Component Tests** - React component behavior
- **E2E Tests** - Full user workflows (planned)

## 🔐 Security Features

### Authentication & Authorization
- JWT-based authentication
- Social OAuth (GitHub, Microsoft)
- Email verification system
- Password reset functionality
- Role-based access control

### Security Scanning Capabilities
- **HTTP Headers Analysis** - Security headers validation
- **SSL/TLS Configuration** - Certificate and protocol analysis
- **Vulnerability Scanning** - Common web vulnerabilities
- **Content Analysis** - SEO and security content review
- **Port Scanning** - Open port detection
- **CSP Analysis** - Content Security Policy evaluation
- **Cookie Security** - Cookie configuration analysis
- **CORS Configuration** - Cross-origin policy review
- **Server Analysis** - Server information disclosure

### AI-Powered Features
- **Anomaly Detection** - Pattern recognition in security data
- **Risk Scoring** - Automated security risk assessment
- **Threat Intelligence** - Integration with threat databases
- **Recommendations** - AI-generated security improvements
- **Trend Analysis** - Historical security trend identification

## 📊 Data Flow Architecture

### Frontend to Backend Communication
1. **Authentication Flow**
   - User login/registration → AuthService → Django Auth
   - JWT token storage and refresh
   - Social OAuth integration

2. **Scanning Flow**
   - Scan request → ScanService → Django Scanner
   - Real-time progress updates
   - Result processing and storage

3. **Reporting Flow**
   - Report generation → ReportService → Django Reports
   - PDF export functionality
   - Virtual report creation

4. **AI Analysis Flow**
   - Scan data → AIService → Django AI Analyzer
   - Machine learning processing
   - Recommendation generation

## 🚀 Development Workflow

### Getting Started
1. **Clone repository**
   ```bash
   git clone <repository-url>
   cd site-analyser
   ```

2. **Setup with Docker**
   ```bash
   docker-compose up -d
   ```

3. **Development mode**
   ```bash
   # Frontend
   cd client
   npm install
   npm start

   # Backend
   cd server
   pip install -r requirements.txt
   python manage.py runserver
   ```

### Testing
```bash
# Frontend tests
cd client
npm test

# Backend tests
cd server
python manage.py test
```

### Building for Production
```bash
# Build frontend
cd client
npm run build

# Build Docker images
docker-compose -f docker-compose.prod.yml build
```

## 📈 Future Enhancements

### Planned Features
- **Advanced AI Models** - Custom-trained security models
- **Real-time Monitoring** - Continuous security monitoring
- **Compliance Reporting** - GDPR, SOC2, ISO27001 compliance
- **API Rate Limiting** - Enhanced API protection
- **Multi-tenant Support** - Organization-based access
- **Mobile App** - React Native mobile application
- **Webhook Integration** - External system notifications
- **Advanced Analytics** - Security trend dashboards

### Performance Optimizations
- **Caching Strategy** - Redis-based caching
- **Database Optimization** - Query optimization and indexing
- **CDN Integration** - Static asset delivery
- **Load Balancing** - Horizontal scaling support

This structure provides a comprehensive, scalable foundation for a modern web security analysis platform with AI-powered insights and automated reporting capabilities.