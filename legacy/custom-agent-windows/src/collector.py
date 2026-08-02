from __future__ import annotations

import argparse
import json
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .collectors.network import (
    collect_connections,
    evaluate_attack_vector,
    get_open_listening_ports,
)
from .collectors.privilege import get_current_privileges
from .collectors.system import (
    get_cpu_info,
    get_defender_status,
    get_device_info,
    get_disk_info,
    get_firewall_status,
    get_memory_info,
    get_system32_inventory,
)
from .config import AppConfig, load_config
from .identity import load_or_create_identity, utc_now_iso
from .logging_config import configure_logging


CollectorFunction = Callable[[], Any]


def _safe_collect(
    name: str,
    function: CollectorFunction,
    errors: list[dict[str, str]],
    logger: logging.Logger,
) -> Any:
    started = time.perf_counter()

    try:
        result = function()
        logger.debug(
            "Collector %s completed in %.2f ms",
            name,
            (time.perf_counter() - started) * 1000,
        )
        return result
    except Exception as error:
        logger.exception("Collector %s failed", name)
        errors.append(
            {
                "collector": name,
                "message": str(error),
            }
        )
        return None


def collect_agent_data(
    config: AppConfig,
    *,
    scan_id: str | None = None,
    device_id: str | None = None,
    skip_system32: bool = False,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    active_logger = logger or configure_logging(config.agent.log_directory)
    identity = load_or_create_identity(config.agent.data_directory)
    collector_errors: list[dict[str, str]] = []
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    effective_scan_id = scan_id or str(uuid.uuid4())

    active_logger.info("Starting scan %s", effective_scan_id)

    monitored_connections = _safe_collect(
        "monitoredConnections",
        lambda: collect_connections(
            config.agent.monitored_ports,
            config.agent.max_network_connections,
        ),
        collector_errors,
        active_logger,
    )

    connection_items = (
        monitored_connections.get("items", [])
        if isinstance(monitored_connections, dict)
        else []
    )

    system32_inventory: Any
    if skip_system32:
        system32_inventory = {
            "items": [],
            "scannedCount": 0,
            "truncated": False,
            "recursive": config.agent.system32_recursive,
            "available": False,
            "skipped": True,
        }
    else:
        system32_inventory = _safe_collect(
            "system32Inventory",
            lambda: get_system32_inventory(
                config.agent.system32_file_limit,
                config.agent.system32_recursive,
            ),
            collector_errors,
            active_logger,
        )

    payload = {
        "schemaVersion": config.agent.schema_version,
        "agentVersion": config.agent.version,
        "scanId": effective_scan_id,
        "deviceId": device_id,
        "agentInstallationId": identity["installationId"],
        "collectedAtUtc": utc_now_iso(),
        "collectionStartedAtUtc": started_at.isoformat().replace("+00:00", "Z"),
        "collectionDurationMs": round((time.perf_counter() - started) * 1000),
        "collectorErrors": collector_errors,
        "data": {
            "deviceInfo": _safe_collect(
                "deviceInfo", get_device_info, collector_errors, active_logger
            ),
            "privilege": _safe_collect(
                "privilege",
                get_current_privileges,
                collector_errors,
                active_logger,
            ),
            "firewall": _safe_collect(
                "firewall",
                lambda: get_firewall_status(
                    config.agent.powershell_timeout_seconds
                ),
                collector_errors,
                active_logger,
            ),
            "defender": _safe_collect(
                "defender",
                lambda: get_defender_status(
                    config.agent.powershell_timeout_seconds
                ),
                collector_errors,
                active_logger,
            ),
            "cpu": _safe_collect(
                "cpu", get_cpu_info, collector_errors, active_logger
            ),
            "memory": _safe_collect(
                "memory", get_memory_info, collector_errors, active_logger
            ),
            "disk": _safe_collect(
                "disk", get_disk_info, collector_errors, active_logger
            ),
            "openListeningPorts": _safe_collect(
                "openListeningPorts",
                get_open_listening_ports,
                collector_errors,
                active_logger,
            ),
            "monitoredConnections": monitored_connections,
            "attackVector": evaluate_attack_vector(connection_items),
            "system32Inventory": system32_inventory,
        },
    }

    payload["collectionDurationMs"] = round(
        (time.perf_counter() - started) * 1000
    )
    active_logger.info(
        "Completed scan %s in %s ms with %s collector errors",
        effective_scan_id,
        payload["collectionDurationMs"],
        len(collector_errors),
    )
    return payload


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def save_scan_payload(config: AppConfig, payload: dict[str, Any]) -> Path:
    scan_id = str(payload["scanId"])
    scan_path = config.agent.data_directory / f"scan-{scan_id}.json"
    latest_path = config.agent.data_directory / "latest-scan.json"

    _atomic_write_json(scan_path, payload)
    _atomic_write_json(latest_path, payload)
    return scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one CYRP system scan")
    parser.add_argument("--config", default=None)
    parser.add_argument("--scan-id", default=None)
    parser.add_argument("--device-id", default=None)
    parser.add_argument("--skip-system32", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    config = load_config(arguments.config)
    logger = configure_logging(config.agent.log_directory, arguments.verbose)

    payload = collect_agent_data(
        config,
        scan_id=arguments.scan_id,
        device_id=arguments.device_id,
        skip_system32=arguments.skip_system32,
        logger=logger,
    )
    path = save_scan_payload(config, payload)

    print(f"Scan completed: {payload['scanId']}")
    print(f"Saved payload: {path}")

    if arguments.print_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
