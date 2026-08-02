from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when the agent configuration is missing or invalid."""


@dataclass(frozen=True)
class AgentSettings:
    version: str
    schema_version: str
    data_directory: Path
    log_directory: Path
    system32_file_limit: int
    system32_recursive: bool
    powershell_timeout_seconds: int
    max_network_connections: int
    monitored_ports: tuple[int, ...]


@dataclass(frozen=True)
class ServerSettings:
    base_url: str
    request_timeout_seconds: int
    poll_interval_seconds: int
    long_poll_seconds: int


@dataclass(frozen=True)
class AppConfig:
    root_directory: Path
    source_path: Path
    agent: AgentSettings
    server: ServerSettings


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"'{field_name}' phải là object JSON")
    return value


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{field_name}' phải là chuỗi không rỗng")
    return value.strip()


def _require_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"'{field_name}' phải là số nguyên dương")
    return value


def _resolve_directory(root: Path, value: Any, field_name: str) -> Path:
    directory = Path(_require_string(value, field_name))
    if not directory.is_absolute():
        directory = root / directory
    return directory.resolve()


def _parse_ports(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ConfigError("'agent.monitoredPorts' phải là mảng")

    ports: set[int] = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ConfigError("Mỗi monitored port phải là số nguyên")
        if not 1 <= item <= 65535:
            raise ConfigError(f"Port không hợp lệ: {item}")
        ports.add(item)

    return tuple(sorted(ports))


def _default_config_path(root: Path) -> Path:
    environment_path = os.getenv("CYRP_AGENT_CONFIG")
    if environment_path:
        return Path(environment_path).expanduser().resolve()

    local_config = root / "config.json"
    if local_config.exists():
        return local_config

    return root / "config.example.json"


def load_config(config_path: str | Path | None = None) -> AppConfig:
    root = Path(__file__).resolve().parents[1]
    path = (
        Path(config_path).expanduser().resolve()
        if config_path
        else _default_config_path(root)
    )

    if not path.exists():
        raise ConfigError(f"Không tìm thấy file cấu hình: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"JSON cấu hình không hợp lệ: {error}") from error

    root_object = _require_mapping(raw, "root")
    agent_raw = _require_mapping(root_object.get("agent"), "agent")
    server_raw = _require_mapping(root_object.get("server"), "server")

    data_directory = _resolve_directory(
        root,
        agent_raw.get("dataDirectory"),
        "agent.dataDirectory",
    )
    log_directory = _resolve_directory(
        root,
        agent_raw.get("logDirectory"),
        "agent.logDirectory",
    )

    data_directory.mkdir(parents=True, exist_ok=True)
    log_directory.mkdir(parents=True, exist_ok=True)

    base_url = os.getenv(
        "CYRP_SERVER_BASE_URL",
        _require_string(server_raw.get("baseUrl"), "server.baseUrl"),
    ).rstrip("/")

    if not base_url.startswith(("http://", "https://")):
        raise ConfigError("'server.baseUrl' phải bắt đầu bằng http:// hoặc https://")

    agent = AgentSettings(
        version=_require_string(agent_raw.get("version"), "agent.version"),
        schema_version=_require_string(
            agent_raw.get("schemaVersion"),
            "agent.schemaVersion",
        ),
        data_directory=data_directory,
        log_directory=log_directory,
        system32_file_limit=_require_positive_int(
            agent_raw.get("system32FileLimit"),
            "agent.system32FileLimit",
        ),
        system32_recursive=bool(agent_raw.get("system32Recursive", False)),
        powershell_timeout_seconds=_require_positive_int(
            agent_raw.get("powershellTimeoutSeconds"),
            "agent.powershellTimeoutSeconds",
        ),
        max_network_connections=_require_positive_int(
            agent_raw.get("maxNetworkConnections"),
            "agent.maxNetworkConnections",
        ),
        monitored_ports=_parse_ports(agent_raw.get("monitoredPorts")),
    )

    server = ServerSettings(
        base_url=base_url,
        request_timeout_seconds=_require_positive_int(
            server_raw.get("requestTimeoutSeconds"),
            "server.requestTimeoutSeconds",
        ),
        poll_interval_seconds=_require_positive_int(
            server_raw.get("pollIntervalSeconds"),
            "server.pollIntervalSeconds",
        ),
        long_poll_seconds=_require_positive_int(
            server_raw.get("longPollSeconds"),
            "server.longPollSeconds",
        ),
    )

    return AppConfig(
        root_directory=root,
        source_path=path,
        agent=agent,
        server=server,
    )


def public_config(config: AppConfig) -> dict[str, Any]:
    """Return a JSON-safe configuration without credentials."""
    return {
        "configPath": str(config.source_path),
        "agent": {
            "version": config.agent.version,
            "schemaVersion": config.agent.schema_version,
            "dataDirectory": str(config.agent.data_directory),
            "logDirectory": str(config.agent.log_directory),
            "system32FileLimit": config.agent.system32_file_limit,
            "system32Recursive": config.agent.system32_recursive,
            "powershellTimeoutSeconds": config.agent.powershell_timeout_seconds,
            "maxNetworkConnections": config.agent.max_network_connections,
            "monitoredPorts": list(config.agent.monitored_ports),
        },
        "server": {
            "baseUrl": config.server.base_url,
            "requestTimeoutSeconds": config.server.request_timeout_seconds,
            "pollIntervalSeconds": config.server.poll_interval_seconds,
            "longPollSeconds": config.server.long_poll_seconds,
        },
    }
