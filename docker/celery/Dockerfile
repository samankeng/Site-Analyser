# docker/celery/Dockerfile

FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    postgresql-client \
    netcat-traditional \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy entrypoint script (using your existing celery-entrypoint.sh)
COPY scripts/celery-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy project
COPY . /app/

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/static /app/media \
    && chmod 755 /app/logs /app/static /app/media

# Use entrypoint script
ENTRYPOINT ["/entrypoint.sh"]

# Default command (can be overridden)
CMD ["celery", "--app=celery_app", "worker", "--loglevel=info"]