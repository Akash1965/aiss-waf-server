"""Application settings loaded from environment variables.

Local dev  → no env vars needed (in-memory DuckDB, zero setup)
Production → AISS_DATABASE_URL=duckdb:////data/aiss.duckdb  (set by Docker)

The .duckdb file can be queried directly at any time with:
  duckdb /data/aiss.duckdb
  SELECT * FROM security_events ORDER BY created_at DESC LIMIT 50;
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISS_", case_sensitive=False)

    # Server
    environment: str = "development"
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4

    # Database
    # Dev default → in-memory DuckDB, zero external deps.
    # Production → AISS_DATABASE_URL=duckdb:////data/aiss.duckdb (set by Docker)
    database_url: str = "duckdb:///:memory:"

    # Auth
    secret_key: str = "CHANGE_ME_IN_PRODUCTION_USE_256_BIT_KEY"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    api_key_header: str = "X-API-Key"

    # CVE feed
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    osv_api_url: str = "https://api.osv.dev/v1"
    cve_sync_interval_hours: int = 1

    # Apache Doris — central analytics warehouse
    # Doris uses MySQL protocol; BE host is used for Stream Load HTTP API.
    doris_host: str = "localhost"
    doris_port: int = 9030
    doris_user: str = "root"
    doris_password: str = ""
    doris_database: str = "aiss"
    doris_be_host: str = "localhost"
    doris_be_port: int = 8040

    # gRPC server (agent telemetry + CVE streaming)
    grpc_port: int = 50051

    # Telemetry
    telemetry_batch_size: int = 500
    telemetry_retention_days: int = 90

    # CORS
    # Override with AISS_ALLOWED_ORIGINS env var (comma-separated or JSON list)
    # Production must include the Vercel app URL, e.g.:
    #   AISS_ALLOWED_ORIGINS='["https://nit-mca-forum.vercel.app","http://localhost:3000"]'
    allowed_origins: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        "https://nit-mca-forum.vercel.app",
    ]

    # Rate limiting
    rate_limit_per_minute: int = 1000


settings = Settings()
