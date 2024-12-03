#!/bin/bash

# Ensure all environment variables are loaded from the .env file
echo "Loading environment variables from $ENV_FILE"
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

echo "Waiting for PostgreSQL to start..."

# Wait until PostgreSQL is ready
until pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER"; do
    sleep 1
done

echo "PostgreSQL started"

# Check if the initialization SQL script exists, then run it
if [ -f /app/scripts/init.sql ]; then
    echo "Running the database initialization script..."
    PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /app/scripts/init.sql
    echo "Initialization Complete"
fi

# Execute the original command passed to the entrypoint (i.e., running the app)
exec "$@"
