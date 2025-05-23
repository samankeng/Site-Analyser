#!/bin/sh

# Exit immediately if a command exits with a non-zero status
set -e

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

# Execute the command passed to docker run
exec "$@"