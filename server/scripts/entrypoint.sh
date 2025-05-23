#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

# Function to wait for a service
wait_for_service() {
  local host=$1
  local port=$2
  local service=$3
  local max_attempts=30
  local attempt=0
  echo "Waiting for $service to be ready..."
  
  until nc -z $host $port || [ $attempt -eq $max_attempts ]; do
    attempt=$((attempt+1))
    echo "Attempt $attempt/$max_attempts: $service not available yet, waiting..."
    sleep 1
  done
  
  if [ $attempt -eq $max_attempts ]; then
    echo "Error: $service ($host:$port) not available after $max_attempts attempts, exiting"
    exit 1
  else
    echo "$service is ready!"
  fi
}

# Wait for PostgreSQL using pg_isready for better reliability
echo "Waiting for PostgreSQL..."
pg_ready=0
attempts=0
max_attempts=30

while [ $pg_ready -eq 0 ] && [ $attempts -lt $max_attempts ]; do
  if pg_isready -h $DB_HOST -p $DB_PORT -U $POSTGRES_USER; then
    pg_ready=1
  else
    attempts=$((attempts+1))
    echo "Attempt $attempts/$max_attempts: PostgreSQL not available yet, waiting..."
    sleep 1
  fi
done

if [ $pg_ready -eq 0 ]; then
  echo "Error: PostgreSQL not available after $max_attempts attempts, exiting"
  exit 1
else
  echo "PostgreSQL is ready!"
fi

# Wait for Redis
wait_for_service $REDIS_HOST $REDIS_PORT "Redis"

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate

# Apply OAuth specific migrations
echo "Applying OAuth migrations..."
python manage.py migrate social_django

# Create accounts migrations if they don't exist
echo "Creating accounts migrations..."
python manage.py makemigrations accounts || echo "No new migrations to create for accounts"

# Apply accounts migrations
echo "Applying accounts migrations..."
python manage.py migrate accounts

# Create superuser if needed (optional)
if [ "$DJANGO_SUPERUSER_USERNAME" ] && [ "$DJANGO_SUPERUSER_EMAIL" ] && [ "$DJANGO_SUPERUSER_PASSWORD" ]; then
    echo "Creating superuser..."
    python manage.py createsuperuser --noinput
fi

# Execute the command passed to docker run
exec "$@"