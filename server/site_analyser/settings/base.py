# server/site_analyser/settings/base.py - Fixed logging configuration

import os
from pathlib import Path
from datetime import timedelta
from .security_compliance import *
import dj_database_url

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Create logs directory if it doesn't exist
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOGS_DIR, exist_ok=True)

# Prevent content type sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# Enable browser XSS protection (modern browsers ignore this but harmless)
SECURE_BROWSER_XSS_FILTER = True

# Only allow site to be rendered in frames from the same origin
X_FRAME_OPTIONS = 'DENY'

# Enforce HTTPS for 1 year
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Referrer policy to protect privacy
SECURE_REFERRER_POLICY = 'no-referrer-when-downgrade'

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-key-for-development')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_celery_beat',
    'django_celery_results',
    'drf_yasg',
    
    # Local apps
    'accounts',
    'scanner',
    #'reports',
    'alerts',
    'ai_analyzer',
    'api',
    'compliance',

    # social signup
    'social_django',
    'oauth2_provider',
    'csp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',
    

    # social signup
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
]

# Additional security settings for production
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = True  # Already in production.py
SESSION_COOKIE_SECURE = True  # Already in production.py
CSRF_COOKIE_SECURE = True  # Already in production.py
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
ROOT_URLCONF = 'site_analyser.urls'

# CSRF settings for your React frontend
CSRF_TRUSTED_ORIGINS = [
    'https://humble-spirit-production.up.railway.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
]


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'site_analyser.wsgi.application'

# Database
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # Production (Railway) - use DATABASE_URL
    DATABASES = {
        'default': dj_database_url.parse(DATABASE_URL)
    }
else:
    # Local development - use individual variables
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DB_NAME', 'site_analyser'),
            'USER': os.environ.get('DB_USER', 'postgres'),
            'PASSWORD': os.environ.get('DB_PASSWORD', 'postgres'),
            'HOST': os.environ.get('DB_HOST', 'localhost'),
            'PORT': os.environ.get('DB_PORT', '5432'),
            'OPTIONS': {
                'connect_timeout': 10,
                'keepalives': 1,
                'keepalives_idle': 30,
                'keepalives_interval': 10,
                'keepalives_count': 5,
            }
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

CORS_ALLOWED_HEADERS = [
    'authorization',
    'content-type',
    'x-csrftoken',
    'x-requested-with',
    'accept',
    'accept-encoding',
    'accept-language',
    'host',
    'origin',
    'user-agent',
    'x-requested-with',
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'accounts.User'



REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 1000,
    # Add this to disable browsable API
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

# JWT settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "https://humble-spirit-production.up.railway.app",  # Your frontend URL
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ALLOW_CREDENTIALS = True

# Celery settings
# Celery settings - FIXED for Railway
REDIS_URL = os.environ.get('REDIS_URL')

if REDIS_URL:
    # Production (Railway) - use REDIS_URL
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
else:
    # Local development - use localhost
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 60  # 1 minute
CELERY_TASK_ALWAYS_EAGER = False  # Don't run tasks synchronously
CELERY_TASK_EAGER_PROPAGATES = False

# AI/ML Settings
LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'openai')  # 'openai', 'ollama', etc.

# OpenAI Settings
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
OPENAI_MODEL_NAME = os.environ.get('OPENAI_MODEL_NAME', 'gpt-4o')

# Ollama Settings
OLLAMA_BASE_URL = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_MODEL_NAME = os.environ.get('OLLAMA_MODEL_NAME', 'llama3')

# Social Auth Settings
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.getenv('GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.getenv('GOOGLE_OAUTH2_SECRET')
SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

SOCIAL_AUTH_GITHUB_KEY = os.getenv('GITHUB_KEY')
SOCIAL_AUTH_GITHUB_SECRET = os.getenv('GITHUB_SECRET')
SOCIAL_AUTH_GITHUB_SCOPE = ['user:email']

# Microsoft OAuth Settings
SOCIAL_AUTH_MICROSOFT_GRAPH_KEY = os.getenv('MICROSOFT_CLIENT_ID')
SOCIAL_AUTH_MICROSOFT_GRAPH_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
SOCIAL_AUTH_MICROSOFT_GRAPH_SCOPE = ['openid', 'email', 'profile']

# Pipeline for social auth
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.user.create_user',
    'accounts.pipeline.create_social_profile',  # Custom pipeline
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)

# OAuth2 Provider Settings
OAUTH2_PROVIDER = {
    'SCOPES': {
        'read': 'Read scope',
        'write': 'Write scope',
    },
    'ACCESS_TOKEN_EXPIRE_SECONDS': 3600,
    'REFRESH_TOKEN_EXPIRE_SECONDS': 24 * 60 * 60,
}

# Social auth URLs
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/dashboard/'
SOCIAL_AUTH_LOGIN_ERROR_URL = '/auth/error/'
SOCIAL_AUTH_DISCONNECT_REDIRECT_URL = '/settings/'

# JWT Settings for social auth
SOCIAL_AUTH_JSONFIELD_ENABLED = True

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.microsoft.MicrosoftOAuth2',
    'django.contrib.auth.backends.ModelBackend',
]

# OAuth settings for views (Required for our custom OAuth endpoints)
GITHUB_KEY = os.getenv('GITHUB_KEY')
GITHUB_SECRET = os.getenv('GITHUB_SECRET')
GOOGLE_OAUTH2_KEY = os.getenv('GOOGLE_OAUTH2_KEY')
GOOGLE_OAUTH2_SECRET = os.getenv('GOOGLE_OAUTH2_SECRET')
MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID')
MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')

# Email Configuration
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@siteanalyser.com')

# Email verification settings
EMAIL_VERIFICATION_TOKEN_LIFETIME = 24  # hours
EMAIL_VERIFICATION_MAX_ATTEMPTS = 3  # per hour
EMAIL_VERIFICATION_BLOCK_DURATION = 1  # hours

# AI Analyzer Configuration
AI_ANALYZER_ENABLED = bool(os.environ.get('AI_ANALYZER_ENABLED', True))

# ML Models Directory
ML_MODELS_DIR = os.path.join(BASE_DIR, 'ml_models')

# Threat Intelligence Configuration
THREAT_INTEL_CACHE_TIMEOUT = int(os.environ.get('THREAT_INTEL_CACHE_TIMEOUT', 86400))  # 24 hours
THREAT_INTEL_MOCK_ENABLED = bool(os.environ.get('THREAT_INTEL_MOCK_ENABLED', True))


# NEW django-csp v4.0+ format:
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': (
            "'self'", 
            "'unsafe-inline'", 
            "'unsafe-eval'",
            "https://cdnjs.cloudflare.com",  # If you use CDN scripts
        ),
        'style-src': (
            "'self'", 
            "'unsafe-inline'",
            "https://fonts.googleapis.com",  # Google Fonts CSS
        ),
        'img-src': (
            "'self'", 
            "data:", 
            "https:", 
            "blob:",  # For generated images
        ),
        'font-src': (
            "'self'", 
            "https:", 
            "data:",
            "https://fonts.gstatic.com",  # Google Fonts
        ),
        'connect-src': (
            "'self'", 
            "https:", 
            "wss:", 
            "ws:",
            "https://humble-spirit-production.up.railway.app",  # Your backend API
            "http://localhost:8000",  # Local development API
        ),
        'frame-ancestors': ("'none'",),
        'base-uri': ("'self'",),
        'object-src': ("'none'",),
        'form-action': ("'self'",),
    }
}



# Permissions Policy (replaces Feature Policy)
PERMISSIONS_POLICY = {
    'accelerometer': [],
    'camera': [],
    'geolocation': [],
    'gyroscope': [],
    'magnetometer': [],
    'microphone': [],
    'payment': [],
    'usb': [],
}


# Enhanced Logging configuration (FIXED)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        # Only create file handler if we can write to the logs directory
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOGS_DIR, 'django.log'),
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'verbose',
        } if os.access(LOGS_DIR, os.W_OK) else {
            'level': 'INFO', 
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'accounts': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


