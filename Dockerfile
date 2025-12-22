# Cloudflare DDNS Updater Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY cloudflare_ddns.py .
COPY config.yaml.example .
COPY config.yaml .

# Create logs directory
RUN mkdir -p /app/logs

# Set permissions
RUN chmod +x cloudflare_ddns.py

# Create a non-root user (optional, but better security)
RUN useradd -m -u 1000 ddns && \
    chown -R ddns:ddns /app

# Switch to non-root user
USER ddns

# Healthcheck: Verify the script ran recently by checking log modification time
# Checks every 6 minutes, allows up to 10 minutes since last run (one missed cycle)
HEALTHCHECK --interval=6m --timeout=10s --start-period=30s --retries=2 \
  CMD test -f /app/logs/ddns.log && \
      test $(find /app/logs/ddns.log -mmin -10 | wc -l) -eq 1 || exit 1

# Default command runs the script once
# For continuous operation, use cron or run via docker-compose with restart policy
CMD ["python3", "cloudflare_ddns.py"]
