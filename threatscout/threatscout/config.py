import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    otx_api_key: str = ""
    greynoise_api_key: str = ""
    urlhaus_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""
    nvd_api_key: str = ""

    app_api_key: str = ""
    web_password: str = ""
    app_secret: str = ""

    cache_ttl_hours: int = 24
    sqlite_path: str = str(ROOT / "data" / "threatscout.db")
    sqlite_cache_path: str = str(ROOT / "data" / "cache.db")
    request_timeout: float = 15.0

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    rate_limit: str = "60/minute"

    @model_validator(mode="after")
    def _random_secret_if_empty(self):
        # APP_SECRET bossa her acilista rastgele bir anahtar uret
        if not self.app_secret:
            self.app_secret = secrets.token_hex(32)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
