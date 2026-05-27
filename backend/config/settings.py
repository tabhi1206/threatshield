import os
from typing import List
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and .env file.
    Uses Pydantic validation to ensure all critical backend values are formatted properly.
    """
    
    # Application configuration
    PROJECT_NAME: str = "ThreatShield API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security configs
    JWT_SECRET_KEY: str = "default_secret_key_threat_shield_change_me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS setup (comma-separated string parsed into list of origins)
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000"
    
    # Database config (SQLite defaults)
    DATABASE_URL: str = "sqlite:///./threatshield.db"
    
    # Cybersecurity analysis parameters
    MALICIOUS_THRESHOLD: int = 50
    
    # Pydantic Settings model configuration
    model_config = SettingsConfigDict(
        # Read .env file from the current directory or one level up
        env_file=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """
        Parses the ALLOWED_ORIGINS string into a clean list of URLs for CORS middleware config.
        """
        if not self.ALLOWED_ORIGINS:
            return []
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

# Instantiate the global settings object to be imported and used across the codebase
settings = Settings()
