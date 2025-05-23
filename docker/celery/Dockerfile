# docker/celery/Dockerfile - Updated with OAuth dependencies
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=site_analyser.settings.production

WORKDIR /app

# Install dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    python3-dev \
    libpq-dev \
    netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install django-oauth-toolkit==1.7.1 \
    && pip install social-auth-app-django==5.4.0 \
    && pip install social-auth-core==4.5.1 \
    && pip install requests-oauthlib==1.3.1

# Copy project
COPY . .

# Set entrypoint script as executable
COPY scripts/celery-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create a non-root user and change permissions
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app /entrypoint.sh

# Switch to non-root user
USER appuser

# Run entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

# Start Celery worker
CMD ["celery", "--app=celery_app", "worker", "--loglevel=info"]