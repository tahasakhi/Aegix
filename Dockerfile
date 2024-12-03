# Use an official Python image
FROM python:3.10-slim

# Install dependencies, including PostgreSQL client
RUN apt-get update && apt-get install -y postgresql-client --no-install-recommends && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and .env file
COPY . .
COPY configs/aegix.env .env

# Expose the application port
EXPOSE 8000

# Copy the entrypoint script into the container
COPY backend/entrypoint.sh /app/entrypoint.sh

# Give execution permissions to the entrypoint script
RUN chmod +x /app/entrypoint.sh

# Set the entrypoint to run the script
ENTRYPOINT ["bash", "/app/entrypoint.sh"]

# Command to run the FastAPI app
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
