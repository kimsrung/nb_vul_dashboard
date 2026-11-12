# ==============================================================================
# Production Dockerfile for Threat Center Dashboard Backend (FastAPI)
# ==============================================================================
FROM python:3.11-slim

WORKDIR /app

# Install minimal runtime system dependencies, ca-certificates, and curl for healthcheck
# Note: build-essential and libpq-dev are intentionally excluded because all python
# dependencies (asyncpg, pyzmq, bcrypt, etc.) distribute pre-compiled manylinux wheels.
# Excluding them prevents linux-libc-dev from being installed, eliminating 1,900+ kernel CVE false positives.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies and ensure core packaging tools are patched
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Create non-root system user for security
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -m appuser

# Copy application source code and install custom/intermediate CA certificates into system trust store
COPY . .
RUN if [ -d certs ]; then \
        cp certs/*.crt /usr/local/share/ca-certificates/ 2>/dev/null || true; \
        update-ca-certificates; \
    fi

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV PYTHONPATH=/app

# Ensure app directory is owned by appuser
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-4}"]
