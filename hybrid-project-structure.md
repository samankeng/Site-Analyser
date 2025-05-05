# Site-Analyser: React Frontend + Django Backend

```
site-analyser/
├── .github/                            # GitHub configuration
│   └── workflows/                      # GitHub Actions workflows
│       ├── ci.yml                      # CI workflow
│       └── deploy.yml                  # Deployment workflow
│
├── frontend/                           # React frontend (keep much of your existing structure)
│   ├── public/                         # Static assets
│   │   ├── favicon.ico                 # Site favicon
│   │   ├── index.html                  # HTML template
│   │   ├── manifest.json               # Web app manifest
│   │   └── robots.txt                  # Robots file
│   │
│   ├── src/                            # Source code
│   │   ├── assets/                     # Images, fonts, etc.
│   │   ├── components/                 # Reusable UI components
│   │   │   ├── common/                 # Shared components
│   │   │   ├── dashboard/              # Dashboard-specific components
│   │   │   ├── reports/                # Report-specific components
│   │   │   └── security/               # Security analysis components
│   │   │
│   │   ├── contexts/                   # React context providers
│   │   ├── hooks/                      # Custom React hooks
│   │   ├── pages/                      # Page components
│   │   ├── services/                   # API service integrations
│   │   │   ├── api.js                  # API client setup
│   │   │   ├── authService.js          # Authentication API calls
│   │   │   ├── reportService.js        # Report API calls
│   │   │   └── scanService.js          # Scan API calls
│   │   │
│   │   ├── store/                      # Redux state management
│   │   ├── utils/                      # Utility functions
│   │   ├── App.js                      # Main application component
│   │   ├── index.js                    # Entry point
│   │   ├── routes.js                   # Application routes
│   │   └── theme.js                    # UI theme configuration
│   │
│   ├── .env                            # Environment variables
│   ├── .env.development                # Development environment variables
│   ├── .env.production                 # Production environment variables
│   ├── package.json                    # Dependencies and scripts
│   └── README.md                       # Frontend documentation
│
├── backend/                            # Django backend
│   ├── site_analyser/                  # Django project root
│   │   ├── settings/                   # Django settings modules
│   │   │   ├── __init__.py             
│   │   │   ├── base.py                 # Base settings
│   │   │   ├── development.py          # Development settings
│   │   │   └── production.py           # Production settings
│   │   ├── urls.py                     # Main URL configuration
│   │   ├── wsgi.py                     # WSGI configuration
│   │   └── asgi.py                     # ASGI configuration
│   │
│   ├── accounts/                       # User authentication app
│   │   ├── models.py                   # User model
│   │   ├── serializers.py              # DRF serializers for auth
│   │   ├── views.py                    # API views for auth
│   │   └── urls.py                     # Auth URL routes
│   │
│   ├── scanner/                        # Security scanning app
│   │   ├── models.py                   # Scan and Result models
│   │   ├── serializers.py              # DRF serializers for scans
│   │   ├── views.py                    # API views for scans
│   │   ├── urls.py                     # Scanner URL routes
│   │   └── services/                   # Scan service modules
│   │       ├── content_scanner.py      # Content analysis scanner
│   │       ├── header_scanner.py       # HTTP header scanner
│   │       ├── performance_scanner.py  # Performance scanner
│   │       ├── port_scanner.py         # Port scanning module
│   │       ├── scan_service.py         # Main scan orchestration
│   │       ├── ssl_scanner.py          # SSL/TLS scanner
│   │       └── vulnerability_scanner.py # Vulnerability scanner
│   │
│   ├── reports/                        # Reporting app
│   │   ├── models.py                   # Report models
│   │   ├── serializers.py              # DRF serializers for reports
│   │   ├── views.py                    # API views for reports
│   │   └── urls.py                     # Report URL routes
│   │
│   ├── alerts/                         # Alerts management app
│   │   ├── models.py                   # Alert models
│   │   ├── serializers.py              # DRF serializers for alerts
│   │   ├── views.py                    # API views for alerts
│   │   ├── urls.py                     # Alert URL routes
│   │   └── services/                   # Alert services
│   │       ├── email_service.py        # Email notification service
│   │       └── notification_service.py # General notification service
│   │
│   ├── ai_analyzer/                    # AI analysis app
│   │   ├── models.py                   # AI analysis models
│   │   ├── serializers.py              # DRF serializers for AI
│   │   ├── views.py                    # API views for AI
│   │   ├── urls.py                     # AI analyzer URL routes
│   │   ├── services/                   # AI services
│   │   │   ├── ai_analysis.py          # AI analysis service
│   │   │   ├── ollama_client.py        # Ollama LLM client
│   │   │   └── threat_intelligence.py  # Threat intelligence
│   │   └── ml/                         # Machine learning models
│   │       ├── threat_detection/       # Threat detection models
│   │       ├── anomaly_detection/      # Anomaly detection models
│   │       └── risk_scoring/           # Risk scoring models
│   │
│   ├── integrations/                   # External API integrations
│   │   ├── shodan_service.py           # Shodan API integration
│   │   ├── ssl_labs_service.py         # SSL Labs API integration
│   │   └── virus_total_service.py      # VirusTotal API integration
│   │
│   ├── api/                            # API app for versioning
│   │   ├── urls.py                     # API URL routing
│   │   └── permissions.py              # Custom DRF permissions
│   │
│   ├── celery_app/                     # Celery for async tasks
│   │   ├── celery.py                   # Celery configuration
│   │   └── tasks.py                    # Shared Celery tasks
│   │
│   ├── .env                            # Environment variables
│   ├── manage.py                       # Django management script
│   ├── requirements.txt                # Python dependencies
│   └── README.md                       # Backend documentation
│
├── docker/                             # Docker configuration
│   ├── frontend/                       # Frontend Docker setup
│   │   └── Dockerfile                  # React frontend Dockerfile
│   │
│   ├── backend/                        # Backend Docker setup
│   │   └── Dockerfile                  # Django backend Dockerfile
│   │
│   ├── nginx/                          # Nginx configuration
│   │   ├── Dockerfile                  # Nginx Dockerfile
│   │   └── nginx.conf                  # Nginx configuration
│   │
│   └── docker-compose.yml              # Docker Compose configuration
│
├── terraform/                          # Infrastructure as code
│   ├── modules/                        # Terraform modules
│   └── environments/                   # Environment configurations
│
├── kubernetes/                         # Kubernetes configuration
│   ├── frontend/                       # Frontend K8s configuration
│   ├── backend/                        # Backend K8s configuration
│   └── nginx/                          # Nginx K8s configuration
│
├── docs/                               # Documentation
│   ├── api/                            # API documentation
│   ├── architecture/                   # Architecture diagrams
│   └── user-guides/                    # User documentation
│
├── .gitignore                          # Git ignore file
└── README.md                           # Project documentation
```

