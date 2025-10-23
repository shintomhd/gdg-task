FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential libpq-dev

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Make db and run migrations
RUN flask db init
RUN flask db migrate -m "Initial Migrations"
RUN flask db upgrade

# Expose port
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]
