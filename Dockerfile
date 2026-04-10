# =============================================================================
# ZSE — Zaphenath Security Engine — Production Docker Image
# =============================================================================
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ---- System dependencies ---------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        gnupg \
    && mkdir -p /etc/apt/keyrings \
    # Node.js 20.x (for npm ls dependency analysis)
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---- Security tools ---------------------------------------------------------

# Semgrep (SAST scanner)
RUN pip install --no-cache-dir semgrep

# Checkov (IaC scanner)
RUN pip install --no-cache-dir checkov

# TruffleHog (secret scanner) — download latest release binary
RUN TRUFFLEHOG_VERSION=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog

# Trivy (container/image scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# ---- Application code -------------------------------------------------------
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Fix Windows line endings + make executable
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

# ---- D-070: Non-root user — principle of least privilege --------------------
# Running as root means a compromised container = root on the host's namespace.
# Create a dedicated app user with minimal permissions.
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser \
    # Grant appuser ownership of the app directory and tmp scan workspace
    && chown -R appuser:appgroup /app \
    && mkdir -p /tmp/zse-scans \
    && chown -R appuser:appgroup /tmp/zse-scans \
    # Allow appuser to write to /tmp (needed for git clone and tarball extraction)
    && chmod 1777 /tmp

USER appuser

# ---- Runtime ----------------------------------------------------------------
# D-031: HEALTHCHECK — allows container orchestrators (Docker, Railway, k8s)
# to detect unhealthy state and restart the container automatically.
# /ping returns {"ok": true} within 1s even with DB down (crash-proof endpoint).
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ping || exit 1

# NO hardcoded EXPOSE — Railway sets $PORT dynamically

CMD ["bash", "start.sh"]
