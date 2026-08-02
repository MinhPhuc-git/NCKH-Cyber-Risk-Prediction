from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


def _utc_iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _local_ipv4() -> str | None:
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        connection.connect(("8.8.8.8", 80))
        return str(connection.getsockname()[0])
    except OSError:
        return None
    finally:
        connection.close()


def get_device_info() -> dict[str, Any]:
    return {
        "hostname": platform.node(),
        "localIpv4": _local_ipv4(),
        "operatingSystem": platform.system(),
        "osVersion": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "pythonVersion": platform.python_version(),
        "bootTimeUtc": _utc_iso_from_timestamp(psutil.boot_time()),
    }


def get_cpu_info() -> dict[str, Any]:
    return {
        "usagePercent": psutil.cpu_percent(interval=1),
        "physicalCores": psutil.cpu_count(logical=False),
        "logicalCores": psutil.cpu_count(logical=True),
    }


def get_memory_info() -> dict[str, Any]:
    memory = psutil.virtual_memory()
    return {
        "totalBytes": memory.total,
        "availableBytes": memory.available,
        "usedBytes": memory.used,
        "usedPercent": memory.percent,
    }


def get_disk_info() -> dict[str, Any]:
    if sys.platform == "win32":
        disk_root = f"{os.environ.get('SystemDrive', 'C:')}\\"
    else:
        disk_root = "/"

    disk = psutil.disk_usage(disk_root)
    return {
        "root": disk_root,
        "totalBytes": disk.total,
        "usedBytes": disk.used,
        "freeBytes": disk.free,
        "usedPercent": disk.percent,
    }


def _run_powershell_json(script: str, timeout_seconds: int) -> Any:
    if sys.platform != "win32":
        raise RuntimeError("PowerShell collector chỉ hỗ trợ Windows")

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"$ErrorActionPreference='Stop'; {script}",
    ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )

    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(message or f"PowerShell exit code {completed.returncode}")

    output = completed.stdout.strip()
    if not output:
        return None

    return json.loads(output)


def get_firewall_status(timeout_seconds: int) -> dict[str, Any]:
    try:
        raw = _run_powershell_json(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Depth 3 -Compress",
            timeout_seconds,
        )
    except Exception as error:
        return {
            "available": False,
            "allProfilesEnabled": None,
            "profiles": [],
            "error": str(error),
        }

    profiles_raw = raw if isinstance(raw, list) else [raw]
    profiles = [
        {
            "name": item.get("Name"),
            "enabled": bool(item.get("Enabled")),
        }
        for item in profiles_raw
        if isinstance(item, dict)
    ]

    return {
        "available": True,
        "allProfilesEnabled": bool(profiles) and all(
            profile["enabled"] for profile in profiles
        ),
        "profiles": profiles,
    }


def get_defender_status(timeout_seconds: int) -> dict[str, Any]:
    try:
        defender = _run_powershell_json(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json -Depth 3 -Compress",
            timeout_seconds,
        )
    except Exception as error:
        return {
            "available": False,
            "antivirusEnabled": None,
            "realTimeProtectionEnabled": None,
            "antispywareEnabled": None,
            "signatureLastUpdated": None,
            "error": str(error),
        }

    if not isinstance(defender, dict):
        return {
            "available": False,
            "error": "Phản hồi Windows Defender không hợp lệ",
        }

    return {
        "available": True,
        "serviceEnabled": defender.get("AMServiceEnabled"),
        "antivirusEnabled": defender.get("AntivirusEnabled"),
        "realTimeProtectionEnabled": defender.get("RealTimeProtectionEnabled"),
        "antispywareEnabled": defender.get("AntispywareEnabled"),
        "signatureLastUpdated": defender.get("AntivirusSignatureLastUpdated"),
    }


def normalize_windows_path(path: Path) -> str:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))

    try:
        relative = path.resolve().relative_to(system_root.resolve())
        return str(Path("%SystemRoot%") / relative)
    except (OSError, ValueError):
        return str(path)


def calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_system32_inventory(
    limit_files: int,
    recursive: bool,
) -> dict[str, Any]:
    if sys.platform != "win32":
        return {
            "items": [],
            "scannedCount": 0,
            "truncated": False,
            "recursive": recursive,
            "available": False,
            "error": "System32 collector chỉ hỗ trợ Windows",
        }

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    system32 = system_root / "System32"

    if not system32.exists():
        return {
            "items": [],
            "scannedCount": 0,
            "truncated": False,
            "recursive": recursive,
            "available": False,
            "error": f"Không tìm thấy {system32}",
        }

    items: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    truncated = False

    def candidate_files():
        iterator = system32.rglob("*.exe") if recursive else system32.glob("*.exe")
        yield from sorted(iterator, key=lambda item: item.name.lower())

    for file_path in candidate_files():
        if len(items) >= limit_files:
            truncated = True
            break

        try:
            metadata = file_path.stat()
            items.append(
                {
                    "fileName": file_path.name,
                    "normalizedPath": normalize_windows_path(file_path),
                    "sizeBytes": metadata.st_size,
                    "modifiedAtUtc": _utc_iso_from_timestamp(metadata.st_mtime),
                    "sha256": calculate_sha256(file_path),
                }
            )
        except (OSError, PermissionError) as error:
            if len(errors) < 20:
                errors.append(
                    {
                        "path": normalize_windows_path(file_path),
                        "message": str(error),
                    }
                )

    return {
        "items": items,
        "scannedCount": len(items),
        "truncated": truncated,
        "recursive": recursive,
        "available": True,
        "errors": errors,
    }
