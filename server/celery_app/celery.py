# backend/celery_app/celery.py

import os
from celery import Celery

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'site_analyser.settings.base')

# Create Celery app
app = Celery('site_analyser')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Use Redis service name instead of localhost
app.conf.broker_url = 'redis://redis:6379/0'
app.conf.result_backend = 'redis://redis:6379/0'

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True, soft_time_limit=120)
def debug_task(self):
    print(f'Request: {self.request!r}')



