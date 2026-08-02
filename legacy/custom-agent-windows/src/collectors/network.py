from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable

import psutil


def _address_parts(address: Any) -> tuple[str | None, int | None]:
    if not address:
        return None, None

    ip_value = getattr(address, "ip", None)
    port_value = getattr(address, "port", None)

    if ip_value is None and isinstance(address, tuple) and len(address) >= 2:
        ip_value = address[0]
        port_value = address[1]

    return (
        str(ip_value) if ip_value is not None else None,
        int(port_value) if port_value is not None else None,
    )


def _format_address(ip_value: str | None, port: int | None) -> str | None:
    if ip_value is None or port is None:
        return None
    if ":" in ip_value:
        return f"[{ip_value}]:{port}"
    return f"{ip_value}:{port}"


def _process_name(pid: int | None) -> str | None:
    if pid is None:
        return None

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def collect_connections(
    monitored_ports: Iterable[int],
    max_connections: int,
) -> dict[str, Any]:
    monitored = set(monitored_ports)
    items: list[dict[str, Any]] = []
    inspected = 0
    denied = False

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return {
            "items": [],
            "inspectedCount": 0,
            "truncated": False,
            "accessDenied": True,
            "error": "Cần chạy Agent bằng quyền Administrator để đọc đầy đủ kết nối",
        }

    for connection in connections:
        inspected += 1
        local_ip, local_port = _address_parts(connection.laddr)
        remote_ip, remote_port = _address_parts(connection.raddr)

        if local_port not in monitored and remote_port not in monitored:
            continue

        items.append(
            {
                "transport": (
                    "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
                ),
                "localIp": local_ip,
                "localPort": local_port,
                "localAddress": _format_address(local_ip, local_port),
                "remoteIp": remote_ip,
                "remotePort": remote_port,
                "remoteAddress": _format_address(remote_ip, remote_port),
                "status": connection.status or None,
                "pid": connection.pid,
                "processName": _process_name(connection.pid),
            }
        )

        if len(items) >= max_connections:
            break

    return {
        "items": items,
        "inspectedCount": inspected,
        "truncated": len(items) >= max_connections,
        "accessDenied": denied,
    }


def get_open_listening_ports() -> dict[str, Any]:
    ports: set[int] = set()

    try:
        for connection in psutil.net_connections(kind="inet"):
            if connection.status != psutil.CONN_LISTEN:
                continue
            _, local_port = _address_parts(connection.laddr)
            if local_port is not None:
                ports.add(local_port)
    except psutil.AccessDenied:
        return {
            "ports": [],
            "accessDenied": True,
            "error": "Không đủ quyền đọc danh sách port",
        }

    return {
        "ports": sorted(ports),
        "accessDenied": False,
    }


def is_private_or_local_ip(ip_value: str | None) -> bool:
    if not ip_value:
        return False

    try:
        address = ipaddress.ip_address(ip_value.split("%", 1)[0])
    except ValueError:
        return False

    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def evaluate_attack_vector(connection_items: list[dict[str, Any]]) -> str:
    has_global_listening = False
    has_lan_listening = False
    has_external_connection = False

    for connection in connection_items:
        status = connection.get("status")
        local_ip = connection.get("localIp")
        remote_ip = connection.get("remoteIp")

        if status == psutil.CONN_LISTEN:
            if local_ip in {"0.0.0.0", "::"}:
                has_global_listening = True
            elif is_private_or_local_ip(local_ip):
                has_lan_listening = True

        if status == psutil.CONN_ESTABLISHED and remote_ip:
            if not is_private_or_local_ip(remote_ip):
                has_external_connection = True

    if has_global_listening:
        return "ADJACENT_OR_NETWORK"
    if has_lan_listening:
        return "ADJACENT"
    if has_external_connection:
        return "LOCAL_WITH_EXTERNAL_CONNECTION"
    return "LOCAL"
