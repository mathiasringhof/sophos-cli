"""Configuration loading for the Sophos CLI."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Connection settings loaded from environment variables or .env files."""

    model_config = SettingsConfigDict(
        env_prefix="SOPHOS_CLI_",
        extra="ignore",
    )

    host: str | None = None
    username: str | None = None
    password: str | None = None
    port: int = 4444
    verify_ssl: bool = True

    @classmethod
    def from_env_file(cls, env_file: Path | None = None) -> Settings:
        kwargs: dict[str, Path] = {}
        if env_file is not None:
            kwargs["_env_file"] = env_file
        return cls(**kwargs)
