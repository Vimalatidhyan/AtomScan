"""Environment configuration."""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration from environment variables."""
    
    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", "./technieum.db")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    API_KEY_HASH_ALGORITHM = "sha256"
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS_PER_HOUR = int(os.getenv("RATE_LIMIT_REQUESTS_PER_HOUR", "1000"))
    RATE_LIMIT_REDIS_URL = os.getenv("RATE_LIMIT_REDIS_URL", None)  # Optional Redis for distributed limiting
    
    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
    
    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
    DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "")
    DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
    SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")
    C99_API_KEY = os.getenv("C99_API_KEY", "")
    
    # External Scanners
    NMAP_PATH = os.getenv("NMAP_PATH", "/usr/bin/nmap")
    NUCLEI_PATH = os.getenv("NUCLEI_PATH", "/usr/local/bin/nuclei")
    SUBFINDER_PATH = os.getenv("SUBFINDER_PATH", "/usr/local/bin/subfinder")
    HTTPX_PATH = os.getenv("HTTPX_PATH", "/usr/local/bin/httpx")
    
    # Scanning
    MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "3600"))
    
    # Webhooks
    WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10"))
    WEBHOOK_MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "./logs/technieum.log")
    
    @classmethod
    def validate(cls):
        """Validate required environment variables."""
        errors = []
        
        if cls.SECRET_KEY == "CHANGE_ME_IN_PRODUCTION":
            errors.append("SECRET_KEY must be set to a secure random value")
        
        # Warn about missing API keys
        if not cls.VIRUSTOTAL_API_KEY:
            errors.append("Warning: VIRUSTOTAL_API_KEY not set - threat intel limited")
        if not cls.SHODAN_API_KEY:
            errors.append("Warning: SHODAN_API_KEY not set - asset enrichment limited")
        
        return errors


# Validate on import
validation_errors = Config.validate()
if validation_errors:
    import logging
    logger = logging.getLogger(__name__)
    for error in validation_errors:
        logger.warning(error)
