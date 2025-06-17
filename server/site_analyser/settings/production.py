# server/site_analyser/settings/production.py
import os
import dj_database_url
from .base import *

# Production settings for Railway deployment

# Security
DEBUG = False
ALLOWED_HOSTS = ['*']  # Railway will provide the domain

# Override the base.py database settings with Railway's PostgreSQL
# Manual database configuration (more reliable than dj-database-url)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'railway',
        'USER': 'postgres',
        'PASSWORD': 'SvndLuoSseeTRnEOXOsJoOZXpdYEouAA',
        'HOST': 'hopper.proxy.rlwy.net',
        'PORT': '48435',
        'OPTIONS': {
            'connect_timeout': 10,
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 5,
        }
    }
}

# Redis/Celery - Use Railway's Redis if available
REDIS_URL = os.environ.get('REDIS_URL')
if REDIS_URL:
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = 'django-db'
    CELERY_TASK_ALWAYS_EAGER = False
else:
    # Fallback: run tasks synchronously
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')


# Override security settings for production
SECURITY_REQUIRE_HTTPS = True
SECURITY_SSL_REDIRECT = True
SECURITY_HEADERS_FORCE = True

# Enhanced security headers for production
SECURITY_HEADERS = {
    'X-XSS-Protection': '1; mode=block',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',  # Stricter in production
    'Permissions-Policy': (
        'accelerometer=(), '
        'camera=(), '
        'geolocation=(), '
        'gyroscope=(), '
        'magnetometer=(), '
        'microphone=(), '
        'payment=(), '
        'usb=(), '
        'interest-cohort=()'  # Block FLoC
    ),
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
}


# Security settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# CORS - Update with your frontend URL
CORS_ALLOWED_ORIGINS = [
    os.environ.get('FRONTEND_URL', 'http://localhost:3000'),
]

# Logging - Use console for Railway
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
    },
}

# Email settings (keep your existing email config)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'