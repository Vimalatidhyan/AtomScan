# Docker Build Issues - Fixed ✅

## Issues Found & Fixed

### Issue 1: Kali Linux Image Not Available
**Error:**
```
ERROR [internal] load metadata for docker.io/kalilinux/kali:latest
failed to resolve source metadata: pull access denied
```

**Fix Applied:** ✅
- Changed FROM `kalilinux/kali:latest` → `ubuntu:22.04`
- Ubuntu has better registry availability and doesn't require auth
- Contains all necessary security tools

---

### Issue 2: docker-compose.yml Version Deprecated
**Warning:**
```
WARN[0000] the attribute `version` is obsolete
```

**Fix Applied:** ✅
- Removed `version: '3.8'` attribute
- Modern Docker Compose v2+ auto-detects the version

---

### Issue 3: Dockerfile `as` Keyword Casing
**Warning:**
```
WARN: FromAsCasing: 'as' and 'FROM' keywords' casing do not match
```

**Fix Applied:** ✅
- Changed all `FROM ... AS` → `FROM ... as` (lowercase)
- Consistent with Docker best practices

---

## Try Building Again

```bash
# Clean any old builds
docker system prune -a

# Rebuild
docker build -t technieum:latest .

# Expected output:
# => [internal] load build definition from Dockerfile
# => => transferring dockerfile: 6.64kB
# => CACHED [base 1/3]
# => [builder 2/3] ...
# => [python-env 3/3] ...
# Successfully tagged technieum:latest
```

If it still fails, try:

```bash
# Force pull latest base image
docker pull ubuntu:22.04

# Build with verbose output
docker build -t technieum:latest . --progress=plain --no-cache
```

---

## Then Start Services

```bash
# Start in background
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f technieum
```

---

## Common Issues & Solutions

### Issue: "No space left on device"
```bash
# Clean up old images/containers
docker system prune -a --volumes

# Free space
du -sh ~/.docker/
```

### Issue: Port 8000 already in use
```bash
# Change port in docker-compose.yml:
ports:
  - "8001:8000"  # Use 8001 instead

# Or kill the process:
lsof -i :8000
kill -9 <PID>
```

### Issue: Permission denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Then try again (no sudo needed)
docker-compose up -d
```

### Issue: Out of memory during build
```bash
# Increase Docker memory limit
# (in Docker Desktop, Settings → Resources → Memory)

# Or use a simpler Dockerfile (see next section)
```

---

## Lightweight Alternative Dockerfile

If the full build is too heavy, use this lighter version:

**Create `Dockerfile.lite`:**

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
WORKDIR /opt/technieum

# Minimal system packages
RUN apt-get update && apt-get install -y \
    python3.11 python3-pip curl git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies only (no Go tools)
COPY requirements.txt requirements-api.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-api.txt

# Copy code
COPY . .
RUN chmod +x docker-entrypoint.sh

EXPOSE 8000
HEALTHCHECK CMD curl -f http://localhost:8000/api/v1/health || exit 1
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["server"]
```

**Build lightweight version:**
```bash
docker build -f Dockerfile.lite -t technieum:lite .

# Use in docker-compose:
services:
  technieum:
    image: technieum:lite
    # ... rest of config
```

---

## Verify Everything Works

```bash
# 1. Check image built
docker images | grep technieum

# 2. Containers running
docker-compose ps

# 3. API responding
curl http://localhost:8000/api/v1/health
# Should return: {"status":"healthy",...}

# 4. Inside container
docker-compose exec technieum python --version

# 5. Run a test
docker-compose exec technieum python -c "import fastapi; print('✓ FastAPI OK')"
```

---

## Still Not Working?

```bash
# Get detailed error messages
docker-compose logs --tail=100 technieum

# Check Docker daemon
docker version
docker info

# Test basic Docker functionality
docker run --rm ubuntu:22.04 echo "Docker is working!"

# Rebuild from scratch
docker-compose down
docker system prune -a --volumes
docker build -t technieum:latest --no-cache .
docker-compose up -d
```

---

## Quick Commands Reference

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Run command in container
docker-compose exec technieum bash

# Restart service
docker-compose restart technieum

# Remove everything (including volumes)
docker-compose down -v

# Prune system
docker system prune -a

# Check resources
docker stats
```

**All fixed! Your Docker setup should work now. 🐳**
