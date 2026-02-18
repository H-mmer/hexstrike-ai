# HexStrike AI - Multi-Stage Dockerfile
# Builds container images with pre-installed security tools
# Supports quick/standard/complete installation modes

# =============================================================================
# Stage 1: Base - Install Python and dependencies
# =============================================================================
FROM debian:bookworm-slim AS base

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install Python, pip, git, and essential tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /opt/hexstrike-ai

# Copy Python requirements
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# =============================================================================
# Stage 2: Installer - Copy installer scripts
# =============================================================================
FROM base AS installer

# Copy installer code
COPY scripts/installer/ /opt/hexstrike-ai/scripts/installer/
COPY scripts/__init__.py /opt/hexstrike-ai/scripts/

# Make install.sh executable
RUN chmod +x /opt/hexstrike-ai/scripts/installer/install.sh

# =============================================================================
# Stage 3: Quick Mode - Install essential tools (20 tools, ~5 min)
# =============================================================================
FROM installer AS quick-mode

# Run installer in quick mode
RUN python3 -m scripts.installer.main --mode quick --output json || \
    echo "Some tools may have failed to install"

# Copy application code
COPY . /opt/hexstrike-ai/

# Expose server port
EXPOSE 8888

# Run HexStrike server
CMD ["python3", "hexstrike_server.py"]

# =============================================================================
# Stage 4: Standard Mode - Install essential + core tools (36 tools, ~15 min)
# =============================================================================
FROM installer AS standard-mode

# Run installer in standard mode
RUN python3 -m scripts.installer.main --mode standard --output json || \
    echo "Some tools may have failed to install"

# Copy application code
COPY . /opt/hexstrike-ai/

# Expose server port
EXPOSE 8888

# Run HexStrike server
CMD ["python3", "hexstrike_server.py"]

# =============================================================================
# Stage 5: Complete Mode - Install all tools (105 tools, ~30 min)
# =============================================================================
FROM installer AS complete-mode

# Run installer in complete mode
RUN python3 -m scripts.installer.main --mode complete --output json || \
    echo "Some tools may have failed to install"

# Copy application code
COPY . /opt/hexstrike-ai/

# Expose server port
EXPOSE 8888

# Run HexStrike server
CMD ["python3", "hexstrike_server.py"]

# =============================================================================
# Default stage: Standard Mode
# =============================================================================
FROM standard-mode AS default
