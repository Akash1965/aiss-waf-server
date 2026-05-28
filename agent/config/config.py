"""
AISS Agent Configuration
Loads from /etc/aiss/aiss.conf or environment variables
"""
import os
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentConfig:
    agent_id: str = ""
    server_url: str = "http://localhost:8080"
    socket_path: str = "/tmp/aiss.sock"
    duckdb_path: str = "/var/lib/aiss/aiss.duckdb"
    model_path: str = "/var/lib/aiss/model.onnx"
    log_level: str = "INFO"
    mode: str = "enforce"          # enforce | shadow (log-only, no blocking)
    api_key: str = ""
    rules_dir: str = ""
    patterns_file: str = ""

    # Tuning
    verdict_cache_ttl: int = 60          # seconds
    telemetry_batch_size: int = 1000
    telemetry_flush_interval: float = 1.0
    cve_sync_interval: int = 3600        # seconds
    model_check_interval: int = 21600    # seconds
    content_full_scan_limit: int = 10240        # 10 KB
    content_sample_scan_limit: int = 1048576    # 1 MB
    ml_block_threshold: float = 0.85

    # Socket server
    socket_timeout: float = 0.01   # 10ms — Fail-Open if exceeded


def load_config(config_path: str = None) -> AgentConfig:
    cfg = AgentConfig()

    # Resolve paths relative to project for development
    project_root = Path(__file__).parent.parent.parent
    cfg.rules_dir = str(project_root / "rules" / "yara")
    cfg.patterns_file = str(project_root / "rules" / "hyperscan" / "cve_patterns.json")

    # Override from config file if it exists
    paths = [
        config_path,
        "/etc/aiss/aiss.conf",
        str(project_root / "aiss.conf"),
    ]
    for path in paths:
        if path and os.path.exists(path):
            _load_file(cfg, path)
            break

    # Environment variable overrides (AISS_<KEY>=<value>)
    for field_name in cfg.__dataclass_fields__:
        env_key = f"AISS_{field_name.upper()}"
        if env_key in os.environ:
            val = os.environ[env_key]
            field_type = type(getattr(cfg, field_name))
            setattr(cfg, field_name, field_type(val))

    # Generate agent_id if not set
    if not cfg.agent_id:
        import uuid
        cfg.agent_id = str(uuid.uuid4())

    return cfg


def _load_file(cfg: AgentConfig, path: str):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip().replace("-", "_")
                val = val.strip().strip('"').strip("'")
                if hasattr(cfg, key):
                    field_type = type(getattr(cfg, key))
                    try:
                        setattr(cfg, key, field_type(val))
                    except (ValueError, TypeError):
                        pass
