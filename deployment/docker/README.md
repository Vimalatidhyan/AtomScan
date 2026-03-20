# Technieum Docker

## Quick start (API + Web UI)

From the **project root**:

```bash
docker compose -f deployment/docker/docker-compose.yml up -d
```

Then open http://localhost:8000 for the dashboard.

- **API docs**: http://localhost:8000/docs  
- **Health**: http://localhost:8000/api/health  

Data is persisted in Docker volume `technieum-data` (DB at `/app/data/technieum.db` inside the container). Output and logs are written to `output/` and `logs/` on the host if you bind-mount them; the compose file currently uses a volume for DB only.

## Bind-mount DB and output (host directories)

To keep the database and output on the host instead of a named volume, edit `docker-compose.yml`:

```yaml
volumes:
  - ../../output:/app/output
  - ../../logs:/app/logs
  - ../../data:/app/data   # create ./data on host, DB will be data/technieum.db
```

Set `TECHNIEUM_DB_PATH=/app/data/technieum.db` (already set). Create `data` and run:

```bash
mkdir -p data output logs
docker compose -f deployment/docker/docker-compose.yml up -d
```

## Running a scan from the CLI (scanner image)

Build and run a one-off scan with the scanner image (shares the same DB volume as the API):

```bash
docker compose -f deployment/docker/docker-compose.yml --profile tools run --rm scanner -t example.com
```

Or build and run the scanner standalone (DB will be inside the container unless you mount it):

```bash
docker build -f deployment/docker/Dockerfile.scanner -t technieum-scanner .
docker run --rm -v $(pwd)/data:/app/data -v $(pwd)/output:/app/output -e TECHNIEUM_DB_PATH=/app/data/technieum.db technieum-scanner -t example.com
```

## Build API image only

```bash
docker build -f deployment/docker/Dockerfile.api -t technieum-api .
docker run -p 8000:8000 -v technieum-data:/app/data -e TECHNIEUM_DB_PATH=/app/data/technieum.db technieum-api
```
