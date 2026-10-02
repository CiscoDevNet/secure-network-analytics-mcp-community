"""Configuration for the SNA MCP server.

All secrets/credentials are sourced from environment variables ONLY.
Nothing is ever hardcoded (see security policy: no hardcoded credentials).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(explicit_path: str | None = None) -> Path | None:
    """Load key=value pairs from a `.env` file into ``os.environ``.

    Minimal, dependency-free parser. Existing environment variables always win
    (so an MCP client's `env` block or your shell overrides the file), which
    means it is safe to call this unconditionally at startup.

    Search order (first match wins):
      1. ``explicit_path`` if provided, else ``$SNA_ENV_FILE``
      2. ``./.env`` (current working directory)
      3. ``.env`` at the project root (two levels above this file)

    Returns the path that was loaded, or ``None`` if no file was found.
    """
    candidates: list[Path] = []
    chosen = explicit_path or os.environ.get("SNA_ENV_FILE")
    if chosen:
        candidates.append(Path(chosen))
    candidates.append(Path.cwd() / ".env")
    # src/sna_mcp/config.py -> project root is parents[2]
    candidates.append(Path(__file__).resolve().parents[2] / ".env")

    for path in candidates:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Don't clobber variables that are already set in the environment.
            os.environ.setdefault(key, value)
        return path
    return None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class SNAConfig:
    """Runtime configuration, populated from environment variables."""

    host: str
    username: str
    password: str
    tenant_id: str | None = None
    # SNA Managers ship a self-signed cert by default. For lab use we default
    # verification OFF, but it is configurable and should be enabled in prod.
    verify_tls: bool = False
    timeout: float = 30.0
    # Async query polling controls.
    poll_interval: float = 1.0
    poll_timeout: float = 300.0

    @property
    def base_url(self) -> str:
        host = self.host
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/")
        return f"https://{host}".rstrip("/")

    @classmethod
    def from_env(cls) -> "SNAConfig":
        # Auto-load a .env file if present (real env vars still take priority).
        load_dotenv()
        return cls._from_current_env()

    @classmethod
    def _from_current_env(cls) -> "SNAConfig":
        host = os.environ.get("SNA_HOST", "").strip()
        username = os.environ.get("SNA_USERNAME", "").strip()
        password = os.environ.get("SNA_PASSWORD", "")

        missing = [
            name
            for name, value in (
                ("SNA_HOST", host),
                ("SNA_USERNAME", username),
                ("SNA_PASSWORD", password),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Missing required environment variable(s): "
                + ", ".join(missing)
                + ". Set SNA_HOST, SNA_USERNAME, and SNA_PASSWORD."
            )

        tenant = os.environ.get("SNA_TENANT_ID", "").strip() or None

        return cls(
            host=host,
            username=username,
            password=password,
            tenant_id=tenant,
            verify_tls=_env_bool("SNA_VERIFY_TLS", default=False),
            timeout=float(os.environ.get("SNA_TIMEOUT", "30")),
            poll_interval=float(os.environ.get("SNA_POLL_INTERVAL", "1")),
            poll_timeout=float(os.environ.get("SNA_POLL_TIMEOUT", "300")),
        )


@dataclass(frozen=True)
class ISEConfig:
    """ISE ERS API configuration for the ANC (quarantine) module.

    Credentials come from environment variables only; the ERS API uses HTTP
    Basic auth against an ISE ERS admin account on TCP 9060, and ERS must be
    enabled (Administration > System > Settings > ERS Settings).
    """

    host: str
    username: str
    password: str
    port: int = 9060
    verify_tls: bool = False
    timeout: float = 30.0
    # Mutating ANC actions (quarantine/clear) are OFF unless explicitly enabled.
    enable_anc_actions: bool = False

    @property
    def base_url(self) -> str:
        host = self.host
        if host.startswith("http://") or host.startswith("https://"):
            base = host.rstrip("/")
            # If a scheme is given without a port, append the ERS port.
            return base if ":" in host.split("//", 1)[1] else f"{base}:{self.port}"
        return f"https://{host}:{self.port}"

    @classmethod
    def from_env(cls) -> "ISEConfig":
        load_dotenv()
        host = os.environ.get("ISE_HOST", "").strip()
        username = os.environ.get("ISE_USERNAME", "").strip()
        password = os.environ.get("ISE_PASSWORD", "")

        missing = [
            name
            for name, value in (
                ("ISE_HOST", host),
                ("ISE_USERNAME", username),
                ("ISE_PASSWORD", password),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Missing required environment variable(s) for ISE ANC: "
                + ", ".join(missing)
                + ". Set ISE_HOST, ISE_USERNAME, and ISE_PASSWORD (ERS admin)."
            )

        return cls(
            host=host,
            username=username,
            password=password,
            port=int(os.environ.get("ISE_PORT", "9060")),
            verify_tls=_env_bool("ISE_VERIFY_TLS", default=False),
            timeout=float(os.environ.get("ISE_TIMEOUT", "30")),
            enable_anc_actions=_env_bool("ISE_ENABLE_ANC_ACTIONS", default=False),
        )
