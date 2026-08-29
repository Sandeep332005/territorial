# ABHIMANYU X CORE — BOSS OS Docker Image
# Base: BOSS Linux (Indian Government Debian derivative)
# Includes: Python 3.12, Ollama, pre-pulled code model
#
# Build:
#   colima start --cpu 4 --memory 8 --disk 40
#   docker build -f docker/boss-os.Dockerfile -t abhimanyux-boss .
#
# Run:
#   docker run -d -p 8000:8000 -p 11434:11434 --name sentinel abhimanyux-boss
#
# Scan:
#   docker exec sentinel python -m abhimanyux.core.fast_orchestrator /targets/

# ── Stage 1: Build environment ────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime (BOSS OS compatible) ─────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="abhimanyux-core"
LABEL description="ABHIMANYU X CORE on BOSS-compatible base"
LABEL version="2.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    git \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Set up Ollama model directory
ENV OLLAMA_MODELS=/ollama/models
RUN mkdir -p /ollama/models

# Create app directory
WORKDIR /app

# Copy project
COPY . .

# Create non-root user
RUN useradd -m -s /bin/bash scanner && \
    chown -R scanner:scanner /app /ollama
USER scanner

# Pre-pull a small code model during build (optional, comment out for smaller image)
# RUN ollama serve & sleep 3 && ollama pull qwen2.5-coder:7b && kill %1

# Expose ports
EXPOSE 8000 11434

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Startup script
COPY docker/start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
