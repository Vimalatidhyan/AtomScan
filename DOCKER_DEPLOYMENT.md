# Technieum Docker Deployment Guide

## Quick Start

### Development (with hot-reload)
```bash
# Start with live code synchronization
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# API available at http://localhost:8000
```

### Production
```bash
# Set environment variables
cp .env.example .env
nano .env  # Configure API keys and passwords

# Create certificate directories
mkdir -p certs
# Place your SSL certs at certs/cert.pem and certs/key.pem

# Deploy full stack (API, nginx, PostgreSQL, Redis)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## File Reference

### Dockerfile
- **Multi-stage build**: 4 stages for optimized layers
- **Stage 1 (base)**: Ubuntu 22.04 + system tools
- **Stage 2 (builder)**: Go tools (subfinder, httpx, etc.)
- **Stage 3 (python-env)**: Python dependencies
- **Stage 4 (runtime)**: Final app image with health checks
- **Size**: ~2GB (includes network scanning tools)

### docker-compose.yml
- **technieum**: Main API server (SQLite by default)
- **Networks**: Custom bridge (172.20.0.0/16)
- **Volumes**: Named volumes for data persistence
- **Health checks**: 30s interval with 10s timeout
- **Resource limits**: 4 CPU / 8GB RAM

### docker-compose.dev.yml
- **Live sync**: Bind mounts for code directories
- **File watch**: Automatic reload on code changes
- **Debug mode**: TECHNIEUM_DEBUG=true
- **Lower resources**: 2 CPU / 4GB RAM for dev

### docker-compose.prod.yml
- **Nginx**: Reverse proxy with SSL/TLS support
- **PostgreSQL**: 16-alpine for production database
- **Redis**: 7-alpine for caching and job queue
- **Logging**: 50MB max per file, 5 files retention
- **Restart**: always-on policy
- **Higher resources**: 8 CPU / 16GB RAM

## Docker Compose Commands

### Development Workflow
```bash
# Start with hot-reload
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# View logs
docker compose logs -f technieum

# Execute commands inside container
docker compose exec technieum python query.py -t example.com

# Stop all services
docker compose down
```

### Production Deployment
```bash
# Build and start all services
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Check service health
docker compose ps
docker compose logs technieum

# View PostgreSQL database
docker compose exec postgres psql -U technieum -d technieum

# Access Redis cache
docker compose exec redis redis-cli -a $REDIS_PASSWORD

# Stop services (preserve data)
docker compose down

# Full cleanup (removes volumes)
docker compose down -v
```

## Environment Configuration

### .env file (required)
```bash
# API Keys
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
GITHUB_TOKEN=your_token_here

# Production Database & Cache
POSTGRES_PASSWORD=secure-password-here
REDIS_PASSWORD=secure-password-here
```

## Best Practices

### Image Management
- **Build**: `docker build -t technieum:1.0 .`
- **Tag**: `docker tag technieum:latest technieum:prod-1.0`
- **Push**: `docker push your-registry/technieum:prod-1.0`
- **Prune**: `docker image prune -a` (remove unused images)

### Volume Management
- **List**: `docker volume ls`
- **Inspect**: `docker volume inspect technieum-data`
- **Backup**: `docker run --rm -v technieum-data:/data -v $(pwd):/backup ubuntu tar czf /backup/technieum.tar.gz -C /data .`
- **Restore**: `docker run --rm -v technieum-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/technieum.tar.gz -C /data`

### Network Management
- **List**: `docker network ls`
- **Inspect**: `docker network inspect technieum-net`
- **Connect container**: `docker network connect technieum-net container-name`

### Logging & Monitoring
- **View logs**: `docker compose logs --tail=100 -f technieum`
- **Export logs**: `docker compose logs > technieum.log`
- **Resource usage**: `docker stats`
- **Image size**: `docker image ls --format "table {{.Repository}}\t{{.Size}}"`

### Security Best Practices
1. **Never commit secrets**: Use .env files with .gitignore
2. **Use read-only mounts**: `./config:/config:ro`
3. **Limit resources**: Set CPU/memory limits in compose
4. **Health checks**: Enable and monitor regularly
5. **SSL/TLS**: Use nginx for encrypted traffic
6. **Network isolation**: Use custom networks instead of host
7. **Log rotation**: json-file driver with max-size and max-file

## Troubleshooting

### Container won't start
```bash
# Check logs
docker compose logs technieum

# Check health status
docker compose ps

# Inspect container
docker inspect technieum-main
```

### Port already in use
```bash
# Change ports in docker-compose.yml
ports:
  - "9000:8000"  # Host:Container

# Or kill existing process
lsof -i :8000
kill -9 <PID>
```

### Database connection errors
```bash
# Check PostgreSQL is running
docker compose ps postgres

# Connect to database
docker compose exec postgres psql -U technieum -d technieum -c "\dt"

# Check connection from app
docker compose logs technieum | grep -i postgres
```

### Memory/CPU limits exceeded
```bash
# Check current usage
docker stats technieum

# Update compose limits
# Edit docker-compose.prod.yml deploy.resources.limits

# Restart with new limits
docker compose up -d
```

## Performance Tuning

### API Workers
- Development: 1-2 workers
- Production: 4-8 workers (set via API_WORKERS env var)

### Python GC
- Add to Dockerfile: `ENV PYTHONGC="optimize"`
- Reduces memory overhead

### Logging Level
- Development: INFO or DEBUG
- Production: WARNING or ERROR

## Next Steps

1. **Copy nginx config**: `cp nginx.conf.example nginx.conf`
2. **Generate SSL certs**: `mkdir -p certs && openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes`
3. **Configure .env**: `cp .env.example .env && nano .env`
4. **Start development**: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up`
5. **Deploy production**: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
