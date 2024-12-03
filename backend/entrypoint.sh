#!/bin/bash

# Start PostgreSQL in the background (if not already running)
echo "Waiting for PostgreSQL to start..."
until pg_isready -h db -p 5432; do
  sleep 2
done

echo "PostgreSQL started"

# Run the SQL script to initialize the database
echo "Running the database initialization script..."
psql -h db -U aegix -d aegix -f /app/scripts/init_db.sql

# Execute the original command (start the FastAPI app)
exec "$@"
