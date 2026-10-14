from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    secret_key: str = "insecure-dev-key-change-me"
    database_url: str = "sqlite:///./data/app.db"
    auth_docs_dir: str = "./data/authorizations"
    uploads_dir: str = "./data/uploads"
    operator_name: str = "Operator"
    retention_days: int = 0
    app_base_url: str = "http://localhost:8000"

    # Safety limits — deliberately conservative defaults for a non-destructive
    # scanner. These are not meant to be tuned up casually; per-scan intensity
    # opt-in is handled separately in the scan launch flow.
    crawler_max_pages: int = 40
    crawler_request_delay_seconds: float = 0.5
    scan_timeout_seconds: int = 900
    nmap_default_ports: str = "top-1000"

    # Known-CVE lookup for detected service versions (NVD CVE API 2.0). Only the product and
    # version string are sent to NVD -- never anything about the target itself. An API key
    # (free, https://nvd.nist.gov/developers/request-an-api-key) raises NVD's rate limit
    # from 5 to 50 requests per 30 s; without one, lookups are spaced 6 s apart.
    cve_lookup_enabled: bool = True
    nvd_api_key: str = ""
    max_cve_lookups_per_scan: int = 10

    @property
    def data_dir(self) -> Path:
        return Path(self.database_url.replace("sqlite:///", "")).parent

    @property
    def auth_docs_path(self) -> Path:
        return Path(self.auth_docs_dir)

    @property
    def uploads_path(self) -> Path:
        return Path(self.uploads_dir)


settings = Settings()

for path in (settings.data_dir, settings.auth_docs_path, settings.uploads_path):
    path.mkdir(parents=True, exist_ok=True)
