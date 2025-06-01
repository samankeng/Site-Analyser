#!/bin/sh
# server/scripts/celery-entrypoint.sh - Simplified without chmod

# Exit immediately if a command exits with a non-zero status
set -e

echo "Starting Celery entrypoint..."

# Create necessary directories (Docker volumes will handle permissions)
echo "Creating necessary directories..."
mkdir -p /app/logs
mkdir -p /app/static  
mkdir -p /app/media

echo "Directories created successfully"

# Wait for postgres to be ready
echo "Waiting for PostgreSQL..."
while ! pg_isready -h $DB_HOST -p $DB_PORT -U $POSTGRES_USER; do
  sleep 0.1
done
echo "PostgreSQL is ready"

# Wait for redis to be ready
echo "Waiting for Redis..."
while ! nc -z $REDIS_HOST $REDIS_PORT; do
  sleep 0.1
done
echo "Redis is ready"

echo "All services ready. Starting Celery..."

# Execute the command passed to docker run
exec "$@"