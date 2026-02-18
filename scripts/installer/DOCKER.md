# HexStrike AI - Docker Deployment Guide

## Overview

HexStrike AI provides Docker containerization with three pre-built configurations:
- **Quick Mode**: 25 essential tools (~5 min build, ~500MB image)
- **Standard Mode**: 43 essential + core tools (~15 min build, ~1GB image)
- **Complete Mode**: 105 all tools (~30 min build, ~2GB image)

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose 1.29+ (or docker-compose plugin)
- 10GB+ available disk space (for complete mode)
- Internet connection (for package downloads)

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start quick mode (port 8888)
docker-compose up hexstrike-quick

# Start standard mode (port 8889)
docker-compose up hexstrike-standard

# Start complete mode (port 8890)
docker-compose up hexstrike-complete

# Start all modes simultaneously
docker-compose up

# Run in background (detached)
docker-compose up -d hexstrike-standard

# View logs
docker-compose logs -f hexstrike-standard

# Stop services
docker-compose down
```

### Using Docker CLI

```bash
# Build quick mode image
docker build --target quick-mode -t hexstrike:quick .

# Build standard mode image
docker build --target standard-mode -t hexstrike:standard .

# Build complete mode image
docker build --target complete-mode -t hexstrike:complete .

# Run container
docker run -d -p 8888:8888 --name hexstrike hexstrike:standard

# View logs
docker logs -f hexstrike

# Stop container
docker stop hexstrike
docker rm hexstrike
```

## Build Stages

The Dockerfile uses a multi-stage build for optimization:

1. **base**: Debian + Python + dependencies
2. **installer**: Copy installer scripts
3. **quick-mode**: Install essential tools
4. **standard-mode**: Install essential + core tools
5. **complete-mode**: Install all tools

Each stage builds on the previous one using Docker layer caching.

## Service Ports

| Service | Host Port | Container Port | Mode |
|---------|-----------|----------------|------|
| hexstrike-quick | 8888 | 8888 | Quick |
| hexstrike-standard | 8889 | 8888 | Standard |
| hexstrike-complete | 8890 | 8888 | Complete |

## Volume Mounts

```yaml
volumes:
  - ./artifacts:/opt/hexstrike-ai/artifacts  # Scan results
  - ./logs:/opt/hexstrike-ai/logs           # Application logs
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| HEXSTRIKE_MODE | standard | Installation mode |
| HEXSTRIKE_PORT | 8888 | Server port |
| DEBIAN_FRONTEND | noninteractive | Prevent prompts |

## Build Optimization

### Layer Caching

The Dockerfile is optimized for layer caching:
1. Python requirements installed first (rarely change)
2. Installer scripts copied before tools (moderate changes)
3. Application code copied last (frequent changes)

### Build Cache

```bash
# Use build cache
docker build --target standard-mode -t hexstrike:standard .

# Force rebuild (no cache)
docker build --no-cache --target standard-mode -t hexstrike:standard .

# Pull cache from registry
docker build --cache-from hexstrike:standard -t hexstrike:standard .
```

## Health Checks

Access the health endpoint to verify the container:

```bash
curl http://localhost:8888/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "7.0",
  "tools_installed": 43,
  "uptime": "00:05:32"
}
```

## Troubleshooting

### Build Failures

**Problem**: Tool installation fails during build
```
Solution: Some tools may fail on Debian. Check build logs:
  docker build --target standard-mode -t hexstrike:standard . 2>&1 | tee build.log
```

**Problem**: Out of disk space
```
Solution: Clean up Docker images and containers:
  docker system prune -a
  docker volume prune
```

### Runtime Issues

**Problem**: Container exits immediately
```
Solution: Check logs for errors:
  docker logs hexstrike
  docker-compose logs hexstrike-standard
```

**Problem**: Port already in use
```
Solution: Change host port in docker-compose.yml:
  ports:
    - "9888:8888"  # Use different host port
```

## Production Deployment

### Security Hardening

```dockerfile
# Create non-root user
RUN useradd -m -s /bin/bash hexstrike
USER hexstrike

# Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_RAW hexstrike:standard
```

### Resource Limits

```yaml
services:
  hexstrike-standard:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### Secrets Management

```bash
# Use Docker secrets
docker secret create hexstrike_api_key ./api_key.txt

# Mount in container
docker service create \
  --secret hexstrike_api_key \
  --name hexstrike \
  hexstrike:standard
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Build Docker Images

on:
  push:
    branches: [ main, v7.0-dev ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Build images
        run: |
          docker build --target quick-mode -t hexstrike:quick .
          docker build --target standard-mode -t hexstrike:standard .

      - name: Push to registry
        run: |
          docker push hexstrike:standard
```

## Image Registry

### Docker Hub

```bash
# Tag image
docker tag hexstrike:standard username/hexstrike:standard

# Push to Docker Hub
docker push username/hexstrike:standard

# Pull from Docker Hub
docker pull username/hexstrike:standard
```

### Private Registry

```bash
# Tag for private registry
docker tag hexstrike:standard registry.example.com/hexstrike:standard

# Push to private registry
docker push registry.example.com/hexstrike:standard
```

## Maintenance

### Update Images

```bash
# Rebuild with latest changes
docker-compose build hexstrike-standard

# Pull latest base image
docker-compose pull

# Restart with new image
docker-compose up -d hexstrike-standard
```

### Cleanup

```bash
# Remove stopped containers
docker-compose rm

# Remove all HexStrike images
docker images | grep hexstrike | awk '{print $3}' | xargs docker rmi

# Full cleanup (containers + images + volumes)
docker-compose down --rmi all --volumes
```

## Performance Tips

1. **Use BuildKit**: Enable Docker BuildKit for faster builds
   ```bash
   export DOCKER_BUILDKIT=1
   docker build --target standard-mode -t hexstrike:standard .
   ```

2. **Multi-stage optimization**: Build only the stage you need
   ```bash
   docker build --target quick-mode -t hexstrike:quick .  # Faster than complete
   ```

3. **Parallel builds**: Build multiple images simultaneously
   ```bash
   docker-compose build --parallel
   ```

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/hexstrike-ai/issues
- Documentation: See README.md and CLAUDE.md
- Logs: Check `docker logs` or mounted log volumes
