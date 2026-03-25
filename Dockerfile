# ════════════════════════════════════════════════════════════
# VulnVision – Multi-stage Dockerfile
# Stage 1: builder  – installs Python deps in a venv
# Stage 2: runtime  – lean image with only what's needed
# ════════════════════════════════════════════════════════════

# ── Stage 1: builder ─────────────────────────────────────────
FROM python:3.12-slim AS builder

# System packages needed to compile wheels (psycopg2, Pillow, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libjpeg-dev \
        zlib1g-dev \
        libwebp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create and activate a virtual env inside the image
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy only requirements first to maximise layer cache hits
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime ─────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="VulnVision Team" \
      description="VulnVision Security Scanning Platform" \
      version="1.0"

# Runtime-only system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libjpeg62-turbo \
        nmap \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual env from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN groupadd -r vulnvision && useradd -r -g vulnvision -d /app -s /sbin/nologin vulnvision

WORKDIR /app

# Copy application source
COPY --chown=vulnvision:vulnvision . .

# Create directories and set permissions
RUN mkdir -p /app/staticfiles /app/media /app/logs && \
    chown -R vulnvision:vulnvision /app

# Switch to non-root user
USER vulnvision

# Collect static assets at build time
RUN python manage.py collectstatic --noinput --settings=vulnvision.settings 2>/dev/null || true

# Health check: poke Gunicorn HTTP ping
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health/ || exit 1

EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["gunicorn", "vulnvision.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "gthread", \
     "--threads", "2", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "120", \
     "--keepalive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "/app/logs/gunicorn-access.log", \
     "--error-logfile", "/app/logs/gunicorn-error.log", \
     "--log-level", "info"]
