# docker/server/Dockerfile - Updated with OAuth dependencies
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=site_analyser.settings.base

WORKDIR /app

# Install dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    postgresql-client \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    python3-cffi \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libpq-dev \
    netcat-openbsd \
    curl \
    shared-mime-info\
    libglib2.0-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install gunicorn \
    && pip install django-oauth-toolkit==1.7.1 \
    && pip install social-auth-app-django==5.4.0 \
    && pip install social-auth-core==4.5.1 \
    && pip install requests-oauthlib==1.3.1

# Copy project
COPY . .

# Create directories and collect static files
RUN mkdir -p /app/static /app/media /app/logs

# Set entrypoint script as executable
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create a non-root user and change permissions
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app /entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "site_analyser.wsgi:application"]