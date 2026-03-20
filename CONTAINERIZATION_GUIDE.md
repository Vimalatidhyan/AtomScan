# Docker Best Practices Implementation Guide
# Technieum Project Containerization

## Files Created/Updated

### 1. **Dockerfile** (Multi-Stage Build)

**Best Practices Implemented:**

- **Multi-stage builds**: Separates build dependencies from runtime to minimize final image size
  - Stage 1 (base): System dependencies and scanning tools
  - Stage 2 (builder): Go tools compilation with cache mounts
  - Stage 3 (python-deps): Python dependencies with BuildKit cache
  - Stage 4 (runtime): Final production image with only necessary artifacts

- **BuildKit cache mounts**: Reduces build time by caching dependencies
  - `--mount=type=cache,target=/var/cache/apt` for apt packages
  - `--mount=type=cache,target=/root/.cache/pip` for pip packages
  - `--mount=type=cache,target=/root/go/pkg/mod` for Go modules

- **Layer caching optimization**: Instructions ordered by change frequency
  - Base dependencies first (rarely change)
  - Python requirements next
  - Application code last (most frequently changes)

- **Security**:
  - `PYTHONDONTWRITEBYTECODE` prevents bytecode generation
  - `PYTHONUNBUFFERED` improves logging
  - Removed pip cache with `--no-cache-dir`
  - Read-only config volume mounts in compose

- **Health checks**: Built-in endpoint health verification with configurable timeouts
  - Start period: 15s (allows time for service initialization)
  - Interval: 30s (reasonable balance between detection and overhead)
  - Retries: 3 (resilient to transient failures)

---

### 2. **docker-compose.yml** (Production Base)

**Best Practices Implemented:**

- **Networking**: Custom bridge network with predictable subnet
  - Service-to-service communication without exposing ports
  - DNS resolution by container name

- **Volume management**:
  - Named volumes for persistent data (technieum-data, technieum-logs)
  - Config mounted read-only (:ro)
  - Proper volume cleanup on removal

- **Resource limits**: Both hard limits and soft reservations
  - Prevents resource exhaustion
  - Ensures Kubernetes-style behavior for easier orchestration
  - Production defaults: 8GB limit, 4GB reservation

- **Logging configuration**:
  - JSON file driver (built-in, no external dependencies)
  - Max size: 10m, max files: 3 (prevents disk bloat)
  - Labels for filtering and organization

- **Health checks**: Integrated with compose orchestration
  - Services marked unhealthy if checks fail
  - Can trigger restarts in orchestrators

- **Environment variables**:
  - Externalized via `.env` file for secrets
  - Defaults provided for all configurations
  - Documented inline for maintainability

---

### 3. **docker-compose.dev.yml** (Development Overlay)

**Best Practices Implemented:**

- **Live code synchronization**:
  - **Bind mounts**: Direct filesystem sync for immediate changes
    - ./app → /opt/technieum/app
    - ./backend, ./api, ./modules, etc.
  - **Develop watch**: Auto-rebuild on dependency changes
    - `action: sync` for code (instant)
    - `action: rebuild` for requirements files

- **Development-specific settings**:
  - Single API worker for easier debugging
  - Debug mode enabled
  - Lower resource limits (2 CPU, 4GB RAM vs 4 CPU, 8GB)

- **Usage**: Compose automatically merges configurations
  - `docker compose -f docker-compose.yml -f docker-compose.dev.yml up`
  - No modification of production files needed

---

### 4. **docker-compose.prod.yml** (Production Overlay)

**Best Practices Implemented:**

- **Service dependencies with health checks**:
  - `depends_on: service_healthy` ensures ordered startup
  - Services only start when dependencies are healthy

- **Production services**:
  - **Nginx**: Reverse proxy, load balancer, TLS termination
  - **PostgreSQL**: Production database with backup-capable storage
  - **Redis**: Caching and job queue with eviction policy

- **Enhanced resource management**:
  - 8 API workers for concurrency
  - Postgres/Redis with dedicated data volumes
  - Bind mount volumes with explicit device paths for reliability

- **Monitoring**:
  - All services have health checks with appropriate intervals
  - Increased logging verbosity (50MB per file, 5 files)
  - Service labels for log filtering

- **Security**:
  - Strong password requirements (via .env)
  - Redis password protection and memory limits
  - PostgreSQL in isolated network

---

## Environment Configuration

### Required `.env` file for production:

```bash
# PostgreSQL
POSTGRES_PASSWORD=your-strong-postgres-password

# Redis
REDIS_PASSWORD=your-strong-redis-password

# API Keys (optional, set as needed)
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
GITHUB_TOKEN=
SECURITYTRAILS_API_KEY=
VIRUSTOTAL_API_KEY=
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
```

---

## Build and Deployment Commands

### Development:
```bash
# Start with live code sync
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Watch logs
docker compose logs -f technieum

# Shell into container
docker compose exec technieum bash
```

### Production:
```bash
# Build image first (optional, compose auto-builds)
docker build -t technieum:latest .

# Start full production stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify health
docker compose ps
docker compose logs technieum

# Graceful shutdown
docker compose down --remove-orphans
```

### Testing:
```bash
# Validate compose files
docker compose config --quiet

# Dry-run startup
docker compose --dry-run up

# Build without starting
docker compose build --no-cache
```

---

## Performance Optimizations

### BuildKit Improvements (automatic with compose):
- Parallel stage builds
- Cache mounts for pip/apt/go (no redundant downloads)
- Smaller image size due to multi-stage approach

### Runtime Improvements:
- Connection pooling from Redis
- Database caching layer
- Nginx load balancing across API workers
- Automatic resource scaling via docker compose

### Development Workflow:
- Bind mounts eliminate rebuild overhead for code changes
- Develop watch rebuilds only on dependency changes
- Single worker reduces noise during debugging

---

## Security Considerations

1. **Image Security**:
   - Multi-stage keeps build tools out of final image
   - Only runtime dependencies included
   - No secrets embedded in image

2. **Runtime Security**:
   - Read-only config volumes
   - Isolated bridge network
   - Resource limits prevent DOS
   - Health checks enable automatic recovery

3. **Secrets Management**:
   - `.env` file excluded from version control
   - All sensitive values externalized
   - Never committed to git

4. **Network Security**:
   - Services communicate via bridge network
   - Only ports 8000 (API), 80/443 (nginx) exposed to host
   - PostgreSQL/Redis only accessible within network

---

## Troubleshooting

### Container won't start:
```bash
docker compose logs technieum
docker compose exec technieum bash  # Shell into container
```

### Health checks failing:
```bash
docker compose ps  # Check status
docker inspect technieum-main  # Full health info
```

### Rebuild after dependency changes:
```bash
# For requirements.txt changes
docker compose build --no-cache
docker compose up -d

# For code changes in dev
# Automatically synced via develop watch
```

### Check resource usage:
```bash
docker compose stats
docker inspect --format='{{json .State.Health}}' technieum-main | jq
```

---

## Next Steps

1. **Create `.env` file** with production secrets
2. **Configure nginx.conf** for your domain (if using production)
3. **Set up volumes** on host filesystem:
   ```bash
   mkdir -p /var/lib/technieum/{postgres,redis}
   chmod 750 /var/lib/technieum/*
   ```
4. **Test locally** with dev compose first
5. **Deploy to production** with prod compose overlay
6. **Monitor health** regularly with `docker compose ps` and logs
