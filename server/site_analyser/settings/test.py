# server/site_analyser/settings/test.py
from .base import *

# Use in-memory SQLite for faster tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable celery tasks during testing
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Mock external services
SHODAN_API_KEY = 'test_key'
SSL_LABS_API_KEY = 'test_key'
VIRUS_TOTAL_API_KEY = 'test_key'