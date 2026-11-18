"""Application configuration loaded exclusively from environment variables."""

from functools import lru_cache
from typing import List
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = Field(default="development")
    app_name: str = Field(default="RG Studio Management System API")
    api_v1_prefix: str = Field(default="/api/v1")

    # Intentionally empty by default; must be provided via server-side environment variables
    database_url: str = Field(default="")
    database_sync_url: str = Field(default="")
    db_ssl_require: bool = Field(default=True)
    db_pooler_mode: bool = Field(default=True)

    jwt_secret_key: str = Field(default="dev-only-unsafe-change-in-production-32chars")
    jwt_refresh_secret_key: str = Field(
        default="dev-only-refresh-unsafe-change-in-production"
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30, ge=5, le=240)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=30)

    # Optional one-time bootstrap secret required for first-run Admin setup in production
    setup_bootstrap_token: str | None = Field(default=None)

    # External master key (stored in hosting secrets) and optional durable disk mount
    config_encryption_key: str = Field(default="")
    config_encryption_key_previous: str = Field(default="")
    persistent_data_dir: str = Field(default="")
    api_base_url: str = Field(default="")

    lockout_threshold: int = Field(default=5, ge=3, le=20)
    lockout_minutes: int = Field(default=15, ge=1, le=120)

    cors_origins: List[str] = Field(default_factory=list)

    @field_validator("database_url")
    @classmethod
    def validate_async_driver(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned and not cleaned.startswith("postgresql+asyncpg://"):
            raise ValueError(
                "RG_DATABASE_URL must use the 'postgresql+asyncpg://' driver."
            )
        return cleaned

    @field_validator("database_sync_url")
    @classmethod
    def validate_sync_driver(cls, value: str) -> str:
        cleaned = value.strip()
        if cleaned and not cleaned.startswith("postgresql+psycopg://"):
            raise ValueError(
                "RG_DATABASE_SYNC_URL must use the 'postgresql+psycopg://' driver."
            )
        return cleaned

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: str | List[str]) -> List[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.environment.lower() == "production":
            if not self.database_url or not self.database_sync_url:
                raise ValueError(
                    "RG_DATABASE_URL and RG_DATABASE_SYNC_URL are required in production."
                )
            if (
                self.jwt_secret_key.startswith("dev-only-")
                or len(self.jwt_secret_key) < 32
            ):
                raise ValueError(
                    "RG_JWT_SECRET_KEY must be set to a strong 32+ char secret in production."
                )
            if (
                self.jwt_refresh_secret_key.startswith("dev-only-")
                or len(self.jwt_refresh_secret_key) < 32
            ):
                raise ValueError(
                    "RG_JWT_REFRESH_SECRET_KEY must be set to a strong 32+ char secret in production."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
