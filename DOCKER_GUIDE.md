# Technieum — Dockerization Guide

**Complete guide to containerizing Technieum for local development and production deployment.**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Architecture](#docker-architecture)
3. [Step-by-Step Setup](#step-by-step-setup)
4. [Configuration](#configuration)
5. [Running Containers](#running-containers)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Setups](#advanced-setups)

---

## Quick Start

### Prerequisite: Install Docker & Docker Compose

**Windows:**
```powershell
# Download and install Docker Desktop (includes Docker Compose)
# https://www.docker.com/products/docker-desktop
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo usermod -aG docker $USER
```

**macOS:**
```bash
# Use Homebrew
brew install docker docker-compose
# Or download Docker Desktop from https://www.docker.com/products/docker-desktop
```

---

### Option 1: Build & Run (Development)

```bash
# 1. Clone/navigate to project
cd /path/to/technieum

# 2. Build Docker image
docker build -t technieum:latest .

# 3. Run with docker-compose
docker-compose up -d

# 4. Check status
docker-compose ps
docker-compose logs -f technieum

# 5. Access API
curl http://localhost:8000/api/v1/health

# 6. Stop
docker-compose down
```

### Option 2: Pre-built Image (Production)

```bash
# Pull from registry (when available)
docker pull technieum/technieum:latest

# Create .env file with API keys
cp .env.docker.example .env.docker

# Run
docker-compose -f docker-compose.yml --profile production up -d
```

---

## Docker Architecture

### Multi-Stage Build

The Dockerfile uses **4 stages** for optimized image size:

```
STAGE 1: Base
├─ Kali Linux base
├─ System packages
└─ Tool directories

STAGE 2: Builder
├─ Go tools (subfinder, nuclei, httpx, etc.)
└─ Binary compilation

STAGE 3: Python Environment
├─ Python 3.11
├─ pip dependencies
└─ Virtual environment

STAGE 4: Runtime (Final)
├─ Application code
├─ Entrypoint script
├─ Health checks
└─ Exposed ports: 8000, 8001, 9000
```

### Image Size Optimization

- **Base:** ~400 MB (Kali Linux)
- **With packages:** ~1.2 GB
- **Final image:** ~1.5–2 GB

---

## Step-by-Step Setup

### Step 1: Prepare Files

#### 1a. Make entrypoint executable
```bash
chmod +x docker-entrypoint.sh
```

#### 1b. Copy environment template
```bash
cp .env.docker.example .env.docker
```

#### 1c. Edit `.env.docker` with your API keys
```bash
# Edit these critical ones:
SHODAN_API_KEY=sk_your_key
CENSYS_API_ID=your_id
CENSYS_API_SECRET=your_secret
GITHUB_TOKEN=ghp_your_token
```

---

### Step 2: Build Docker Image

#### Development Build (with debugging)
```bash
docker build \
  --tag technieum:latest \
  --tag technieum:dev \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  .
```

#### Production Build (optimized)
```bash
docker build \
  --tag technieum:latest \
  --tag technieum:1.0.0 \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  --progress=plain \
  .
```

#### Check image
```bash
docker images | grep technieum
# Output: technieum  latest  <hash>  <date>  1.5GB
```

---

### Step 3: Configure docker-compose

#### Edit `docker-compose.yml`

The file supports multiple deployment profiles:

```bash
# Default (API + Worker)
docker-compose up -d

# With Nginx reverse proxy
docker-compose --profile production up -d

# With PostgreSQL database
docker-compose --profile postgres up -d

# With Redis caching
docker-compose --profile advanced up -d

# All services
docker-compose --profile production --profile postgres --profile advanced up -d
```

---

### Step 4: Create Named Volumes

```bash
# Volumes are auto-created by docker-compose, but you can pre-create:
docker volume create technieum-data
docker volume create postgres-data
docker volume create redis-data

# List volumes
docker volume ls | grep technieum
```

---

### Step 5: Start Services

#### Start background
```bash
docker-compose up -d
```

#### Start with logs
```bash
docker-compose up
```

#### Check status
```bash
docker-compose ps
```

#### View logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f technieum

# Last 50 lines
docker-compose logs --tail=50 technieum
```

---

### Step 6: Verify Setup

```bash
# 1. Check container running
docker ps | grep technieum

# 2. Check logs
docker-compose logs technieum | grep "Uvicorn running"

# 3. Test API
curl -i http://localhost:8000/api/v1/health

# Expected response:
# HTTP/1.1 200 OK
# {"status":"healthy","version":"1.0.0"}

# 4. Test from container
docker-compose exec technieum curl http://localhost:8000/api/v1/health

# 5. Interactive shell
docker-compose exec technieum bash
```

---

## Configuration

### Environment Variables

All configuration is via `.env.docker` file:

#### API Keys (Critical)
```bash
SHODAN_API_KEY=sk_...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
GITHUB_TOKEN=ghp_...
SECURITYTRAILS_API_KEY=...
```

#### Server Configuration
```bash
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4
TECHNIEUM_WORKER=true
```

#### Scanning Timeouts
```bash
TECHNIEUM_SUBFINDER_TIMEOUT=900
TECHNIEUM_HTTPX_RUN_TIMEOUT=3600
TECHNIEUM_NUCLEI_TIMEOUT=3600
```

#### Database
```bash
# SQLite (default)
TECHNIEUM_DB_PATH=/data/technieum.db

# Or PostgreSQL
DATABASE_URL=postgresql://user:pass@postgres:5432/db
```

---

### Volume Mounting

#### Override config files
```bash
docker-compose -f docker-compose.yml \
  --volume /local/config:/opt/technieum/config:ro \
  up -d
```

#### Data persistence
```yaml
# In docker-compose.yml
volumes:
  - technieum-data:/data              # Persistent
  - ./local-data:/data:cached         # Local mount (macOS)
  - /mnt/data:/data                   # Host mount (Linux)
```

---

## Running Containers

### Run Commands

#### Start API server only
```bash
docker-compose -f docker-compose.yml \
  -e TECHNIEUM_WORKER=false \
  up -d
```

#### Start worker only
```bash
docker run -it \
  --env-file .env.docker \
  -v technieum-data:/data \
  technieum:latest worker
```

#### Run a scan
```bash
docker run -it \
  --env-file .env.docker \
  -v technieum-data:/data \
  technieum:latest scan example.com
```

#### Run query
```bash
docker run -it \
  --env-file .env.docker \
  -v technieum-data:/data \
  technieum:latest query -t example.com --summary
```

#### Interactive shell
```bash
docker run -it \
  --env-file .env.docker \
  -v technieum-data:/data \
  technieum:latest shell
```

### Common Operations

#### View database
```bash
docker-compose exec technieum sqlite3 /data/technieum.db ".tables"
```

#### Clear old scans
```bash
docker-compose exec technieum rm -rf /data/scans/*
```

#### Export results
```bash
docker cp technieum-main:/data/output ./local-export
```

#### Tail logs
```bash
docker-compose logs -f --tail 100 technieum
```

#### View resource usage
```bash
docker stats technieum-main
```

---

## Production Deployment

### Pre-production Checklist

- [ ] API keys configured in `.env.docker`
- [ ] Database persistence enabled (volume mount)
- [ ] Logs centralized (Docker logging driver)
- [ ] SSL/TLS enabled (Nginx reverse proxy)
- [ ] Rate limiting configured
- [ ] Resource limits set (CPU, memory)
- [ ] Health checks passing
- [ ] Backups scheduled (database)

---

### Step 1: Production docker-compose.yml

```bash
# Start with all profiles (Nginx, PostgreSQL, Redis)
docker-compose \
  --profile production \
  --profile postgres \
  --profile advanced \
  -f docker-compose.yml \
  up -d
```

---

### Step 2: Configure Nginx

Create `nginx.conf`:

```nginx
upstream technieum {
    server technieum:8000;
}

server {
    listen 80;
    server_name yourdomain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    
    # Proxy
    location / {
        proxy_pass http://technieum;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

### Step 3: SSL Certificates

#### Option 1: Let's Encrypt (Certbot)
```bash
sudo certbot certonly --standalone -d yourdomain.com
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem certs/server.crt
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem certs/server.key
```

#### Option 2: Self-signed (testing only)
```bash
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes
```

---

### Step 4: Backup Strategy

#### Automated daily backups
```bash
# backup.sh
#!/bin/bash
BACKUP_DIR=/backups/technieum
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T technieum sqlite3 /data/technieum.db ".dump" \
  > $BACKUP_DIR/db-$(date +%Y%m%d-%H%M%S).sql

# Backup volumes
docker run --rm \
  -v technieum-data:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/data-$(date +%Y%m%d-%H%M%S).tar.gz /data

# Keep only last 7 days
find $BACKUP_DIR -mtime +7 -delete
```

#### Schedule with cron
```bash
# Add to crontab
0 2 * * * /path/to/backup.sh >> /var/log/technieum-backup.log 2>&1
```

---

### Step 5: Monitoring

#### Docker health checks
```bash
docker-compose ps
```

#### Prometheus metrics (optional)
```yaml
# docker-compose.yml addition
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    profiles:
      - monitoring
```

#### View metrics
```bash
curl http://localhost:9000/metrics
```

---

## Troubleshooting

### Container won't start

**Problem:** `docker-compose up` fails

**Solution:**
```bash
# 1. Check logs
docker-compose logs technieum

# 2. Common issues:
# - "Address already in use" → Port 8000 taken
docker ps -a | grep 8000

# Change port in docker-compose.yml
ports:
  - "8001:8000"  # Use 8001 instead

# - "Permissions denied" → Run with sudo
sudo docker-compose up

# - "Out of disk space" → Clean up
docker system prune -a
```

---

### Database errors

**Problem:** `database is locked` error

**Solution:**
```bash
# 1. Check process
docker-compose exec technieum lsof /data/technieum.db

# 2. Restart service
docker-compose restart technieum

# 3. If corrupted, restore from backup
docker-compose exec technieum sqlite3 /data/technieum.db "PRAGMA integrity_check;"
```

---

### API not responding

**Problem:** `curl http://localhost:8000/api/v1/health` fails

**Solution:**
```bash
# 1. Check container running
docker ps | grep technieum

# 2. Check logs
docker-compose logs technieum | tail -50

# 3. Verify port binding
docker port technieum-main

# 4. Test from inside container
docker-compose exec technieum curl localhost:8000/api/v1/health

# 5. Check resource limits
docker stats technieum-main
```

---

### High memory usage

**Problem:** Container using too much RAM

**Solution:**
```bash
# 1. Check usage
docker stats technieum-main

# 2. Reduce workers
# Edit docker-compose.yml
environment:
  API_WORKERS: "2"  # Reduce from 4

# 3. Increase heap
environment:
  MALLOC_TRIM_THRESHOLD_: "128000"

# 4. Restart
docker-compose restart technieum
```

---

### Scan not progressing

**Problem:** Scan started but no progress

**Solution:**
```bash
# 1. Check worker
docker-compose ps | grep technieum
# Should show 2 services: API and worker

# 2. Check logs
docker-compose logs technieum | grep -i error

# 3. Verify TECHNIEUM_WORKER=true
docker-compose exec technieum env | grep TECHNIEUM_WORKER

# 4. Manually run scan
docker-compose exec technieum python technieum.py -t example.com
```

---

## Advanced Setups

### Multi-Container Scaling

```yaml
# docker-compose-production.yml
version: '3.8'

services:
  api:
    image: technieum:latest
    environment:
      TECHNIEUM_WORKER: "false"
    ports:
      - "8000:8000"
      - "8001:8000"
      - "8002:8000"
  
  worker:
    image: technieum:latest
    command: worker
    environment:
      TECHNIEUM_WORKER_THREADS: "8"
    deploy:
      replicas: 3

  postgres:
    image: postgres:16-alpine
    command:
      - "postgres"
      - "-c"
      - "shared_buffers=256MB"
      - "-c"
      - "effective_cache_size=1GB"
```

Run with:
```bash
docker-compose -f docker-compose-production.yml up -d
```

---

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: technieum-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: technieum
  template:
    metadata:
      labels:
        app: technieum
    spec:
      containers:
      - name: technieum
        image: technieum:latest
        ports:
        - containerPort: 8000
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        env:
        - name: TECHNIEUM_WORKER
          value: "false"
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: technieum-pvc
```

Deploy:
```bash
kubectl apply -f k8s-deployment.yaml
kubectl get pods -l app=technieum
```

---

### Registry Push

```bash
# Tag image
docker tag technieum:latest myregistry/technieum:1.0.0

# Login
docker login myregistry

# Push
docker push myregistry/technieum:1.0.0

# Pull elsewhere
docker pull myregistry/technieum:1.0.0
```

---

## Summary

✅ **You now have:**
- Multi-stage Dockerfile optimized for size
- docker-compose.yml with profiles (dev, prod, postgres, redis)
- docker-entrypoint.sh for flexible startup
- .env.docker.example for configuration
- Production deployment guide
- Troubleshooting reference

📚 **Next steps:**
1. Build: `docker build -t technieum:latest .`
2. Configure: `cp .env.docker.example .env.docker` → Edit API keys
3. Run: `docker-compose up -d`
4. Test: `curl http://localhost:8000/api/v1/health`
5. Deploy: Follow [Production Deployment](#production-deployment) section

**Questions? Check Troubleshooting above or review logs with:**
```bash
docker-compose logs -f technieum
```
