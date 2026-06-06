"""
Central configuration. Reads environment (.env) once and exposes a Settings
object. No secrets are logged.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional; env may be set externally
    pass


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # LLM
    llm_mode: str = os.getenv("LLM_MODE", "default")
    llm_air_gap: bool = _as_bool(os.getenv("LLM_AIR_GAP"), False)
    require_llm: bool = _as_bool(os.getenv("VENOM_REQUIRE_LLM"), False)

    # Multi-agent fleet (NVIDIA NIM). Base model is DeepSeek; per-role overrides
    # live in venom.agents.roles via VENOM_MODEL_<ROLE> env vars.
    base_model: str = os.getenv("VENOM_BASE_MODEL", "deepseek-ai/deepseek-v4-pro")
    multi_agent: bool = _as_bool(os.getenv("VENOM_MULTI_AGENT"), True)
    # Per-engagement token ceiling for the autonomous agent loop.
    agent_token_budget: int = int(os.getenv("VENOM_AGENT_TOKEN_BUDGET", "300000"))
    # Coverage campaign - how WIDE the multi-objective hunt goes. The agent decomposes
    # the surface into N forbidden-action targets and hunts each (never stops at one).
    campaign_max_targets: int = int(os.getenv("VENOM_CAMPAIGN_MAX_TARGETS", "10"))
    campaign_per_target_calls: int = int(os.getenv("VENOM_CAMPAIGN_PER_TARGET_CALLS", "3"))

    # Burp MCP - KEYLESS. The MCP Server extension runs locally inside Burp and
    # exposes a loopback SSE endpoint; no API key is needed or used.
    burp_mcp_enabled: bool = _as_bool(os.getenv("BURP_MCP_ENABLED"), False)
    burp_mcp_url: str = os.getenv("BURP_MCP_URL", "http://127.0.0.1:9876/sse")

    # Where setup scripts install Burp + the MCP extension.
    tools_dir: Path = Path(os.getenv("VENOM_TOOLS_DIR", "./tools"))

    # Operational
    default_rate_limit_rps: float = float(os.getenv("DEFAULT_RATE_LIMIT_RPS", "5"))
    default_allow_destructive: bool = _as_bool(
        os.getenv("DEFAULT_ALLOW_DESTRUCTIVE"), False
    )
    data_dir: Path = Path(os.getenv("VENOM_DATA_DIR", "./venom_data"))
    rag_index_path: Path = Path(
        os.getenv("RAG_INDEX_PATH", "./venom_data/rag/pentest_writeups.faiss")
    )
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    def engagements_dir(self) -> Path:
        return self.data_dir / "engagements"

    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def has_any_llm_key(self) -> bool:
        # DeepSeek is the PRIMARY provider, so it must be counted here (the old list
        # omitted it, wrongly reporting "no LLM" when only DeepSeek was configured).
        return any(
            os.getenv(k)
            for k in ("DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", "NVIDIA_API_KEY")
        ) or _as_bool(os.getenv("LLM_AIR_GAP"))  # air-gap implies local Ollama


SETTINGS = Settings()


def configure_logging(level: str | None = None) -> None:
    logging.basicConfig(
        level=getattr(logging, (level or SETTINGS.log_level).upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    # Ensure no provider API key / bearer token can ever be written to a log.
    from .utils import SecretLogFilter
    flt = SecretLogFilter()
    for h in logging.getLogger().handlers:
        if not any(isinstance(f, SecretLogFilter) for f in h.filters):
            h.addFilter(flt)
