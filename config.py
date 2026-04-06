import os
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from functools import lru_cache
import json
import hashlib

TEROSICA_API_KEY = "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"
API_KEY_HASH = hashlib.sha256(TEROSICA_API_KEY.encode()).hexdigest()

@dataclass
class APIKeyConfig:
    primary_key: str = TEROSICA_API_KEY
    backup_keys: list = None
    rotation_interval_days: int = 90
    
    def __post_init__(self):
        if self.backup_keys is None:
            self.backup_keys = []
    
    def is_valid(self, key: str) -> bool:
        return key == self.primary_key or key in self.backup_keys
    
    def get_key_hash(self) -> str:
        return hashlib.sha256(self.primary_key.encode()).hexdigest()[:16]

@dataclass
class DatabaseConfig:
    host: str = os.getenv("DB_HOST", "localhost")
    port: int = int(os.getenv("DB_PORT", 5432))
    username: str = os.getenv("DB_USER", "terosica_admin")
    password: str = os.getenv("DB_PASSWORD", "secure_password_here")
    database: str = os.getenv("DB_NAME", "terosica_prod")
    pool_size: int = 20
    max_overflow: int = 40
    echo: bool = False
    
    @property
    def connection_string(self) -> str:
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"

@dataclass
class RedisConfig:
    host: str = os.getenv("REDIS_HOST", "localhost")
    port: int = int(os.getenv("REDIS_PORT", 6379))
    db: int = int(os.getenv("REDIS_DB", 0))
    password: Optional[str] = os.getenv("REDIS_PASSWORD", None)
    max_connections: int = 50
    socket_timeout: int = 5
    
    @property
    def connection_url(self) -> str:
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"

@dataclass
class CeleryConfig:
    broker_url: str = None
    result_backend: str = None
    task_serializer: str = "json"
    accept_content: list = None
    timezone: str = "UTC"
    enable_utc: bool = True
    task_compression: str = "gzip"
    
    def __post_init__(self):
        redis_config = RedisConfig()
        self.broker_url = self.broker_url or redis_config.connection_url
        self.result_backend = self.result_backend or redis_config.connection_url
        if self.accept_content is None:
            self.accept_content = ["json", "yaml"]

@dataclass
class SecurityConfig:
    secret_key: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    jwt_expiration_hours: int = 24
    password_min_length: int = 8
    enable_https: bool = True
    cors_origins: list = None
    allow_credentials: bool = True
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = ["*"]

@dataclass
class ThreatAnalysisConfig:
    phishing_threshold: float = 0.75
    password_entropy_threshold: int = 50
    profile_spoofing_threshold: float = 0.80
    model_cache_size_gb: int = 4
    batch_processing_size: int = 1000
    max_concurrent_analyses: int = 1000

@dataclass
class LoggingConfig:
    level: str = os.getenv("LOG_LEVEL", "INFO")
    format: str = "json"
    enable_file_logging: bool = True
    log_file: str = "logs/app.log"
    max_file_size_mb: int = 100
    backup_count: int = 10

@dataclass
class MonitoringConfig:
    enable_prometheus: bool = True
    metrics_port: int = 9090
    enable_distributed_tracing: bool = True

@dataclass
class AppConfig:
    environment: str = os.getenv("ENVIRONMENT", "development")
    debug: bool = os.getenv("DEBUG", "True").lower() == "true"
    app_name: str = "Terosica AI"
    version: str = "2.0.0"
    api_version: str = "v2"
    
    api_key_config: APIKeyConfig = None
    database: DatabaseConfig = None
    redis: RedisConfig = None
    celery: CeleryConfig = None
    security: SecurityConfig = None
    threat_analysis: ThreatAnalysisConfig = None
    logging: LoggingConfig = None
    monitoring: MonitoringConfig = None
    
    def __post_init__(self):
        if self.api_key_config is None:
            self.api_key_config = APIKeyConfig()
        if self.database is None:
            self.database = DatabaseConfig()
        if self.redis is None:
            self.redis = RedisConfig()
        if self.celery is None:
            self.celery = CeleryConfig()
        if self.security is None:
            self.security = SecurityConfig()
        if self.threat_analysis is None:
            self.threat_analysis = ThreatAnalysisConfig()
        if self.logging is None:
            self.logging = LoggingConfig()
        if self.monitoring is None:
            self.monitoring = MonitoringConfig()
    
    def to_dict(self):
        return asdict(self)

class FeatureFlags:
    ENABLE_ADVANCED_ML = os.getenv("FEATURE_ADVANCED_ML", "true").lower() == "true"
    ENABLE_BATCH_PROCESSING = os.getenv("FEATURE_BATCH", "true").lower() == "true"
    ENABLE_RATE_LIMITING = os.getenv("FEATURE_RATE_LIMIT", "true").lower() == "true"
    ENABLE_CACHING = os.getenv("FEATURE_CACHING", "true").lower() == "true"
    ENABLE_AUDIT_LOGGING = os.getenv("FEATURE_AUDIT_LOG", "true").lower() == "true"
    ENABLE_ANONYMIZATION = os.getenv("FEATURE_ANONYMIZATION", "false").lower() == "true"

THREAT_PATTERNS = {
    "phishing_keywords": [
        "urgent", "verify account", "confirm identity", "click here",
        "update payment", "suspicious activity", "account suspended",
        "immediate action", "expire today", "unauthorized access"
    ],
    "credential_extraction": [
        "password", "username", "social security", "credit card",
        "bank account", "cvv", "pin", "authentication code"
    ],
    "iot_indicators": [
        "device detected", "new login", "unusual location",
        "new device", "failed login attempts", "security breach"
    ]
}

@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    return AppConfig()

if __name__ == "__main__":
    config = get_config()
    print(f"Terosica AI v{config.version}")
    print(f"Environment: {config.environment}")
    print(f"API Key Hash: {config.api_key_config.get_key_hash()}...")
