import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Smart DNS Firewall"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # API
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "sqlite:///./data/logs.db"
    
    # DNS Server
    DNS_BIND_ADDRESS: str = "127.0.0.1"
    DNS_BIND_PORT: int = 5353
    UPSTREAM_DNS: str = "8.8.8.8"  # Google DNS
    UPSTREAM_DNS_PORT: int = 53
    
    # Machine Learning
    ML_MODEL_PATH: str = "./app/ml/model.pkl"
    ML_CONFIDENCE_THRESHOLD: float = 0.8
    ML_REVIEW_THRESHOLD: float = 0.5
    
    # Rule Engine
    RULE_MAX_DOMAIN_LENGTH: int = 50
    RULE_HIGH_ENTROPY_THRESHOLD: float = 4.0
    RULE_SUSPICIOUS_TLDS: list = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
    
    # Blockchain Logging
    BLOCKCHAIN_ENABLED: bool = True
    
    # Redis Cache
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    CACHE_TTL: int = 3600  # 1 hour
    
    # CORS
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000"
    ]
    
    # Threat Intelligence APIs (Optional)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ALIENVAULT_API_KEY: Optional[str] = None
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "./logs/app.log"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()