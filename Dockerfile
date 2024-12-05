# Use an official Python image
FROM python:3.10-slim

# Install dependencies, including PostgreSQL client
RUN apt-get update && apt-get install -y postgresql-client --no-install-recommends && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Set PYTHONPATH so the application can find modules
ENV PYTHONPATH=/app/backend

# Copy the application code and .env file
COPY . .
COPY configs/aegix.env .env

# Ensure the scripts directory is in the correct location
RUN chmod -R 755 /app

# Expose the application port
EXPOSE 8000

# Command to run the FastAPI app
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
