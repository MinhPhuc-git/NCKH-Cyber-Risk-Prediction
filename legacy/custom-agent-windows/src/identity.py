from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IDENTITY_FILENAME = "identity.json"
CREDENTIALS_FILENAME = "credentials.json"


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _atomic_write_json(
    path: Path,
    payload: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor, temporary_name = (
        tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            text=True,
        )
    )

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                payload,
                handle,
                indent=2,
                ensure_ascii=False,
            )
            handle.write("\n")

        os.replace(
            temporary_name,
            path,
        )
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass

        raise


def load_or_create_identity(
    data_directory: Path,
) -> dict[str, str]:
    identity_path = (
        data_directory
        / IDENTITY_FILENAME
    )

    if identity_path.exists():
        payload = json.loads(
            identity_path.read_text(
                encoding="utf-8-sig",
            )
        )

        installation_id = payload.get(
            "installationId"
        )

        created_at = payload.get(
            "createdAtUtc"
        )

        if (
            isinstance(
                installation_id,
                str,
            )
            and isinstance(
                created_at,
                str,
            )
        ):
            uuid.UUID(installation_id)

            return {
                "installationId":
                    installation_id,
                "createdAtUtc":
                    created_at,
            }

        raise ValueError(
            "Identity file không hợp lệ: "
            f"{identity_path}"
        )

    identity = {
        "installationId":
            str(uuid.uuid4()),
        "createdAtUtc":
            utc_now_iso(),
    }

    _atomic_write_json(
        identity_path,
        identity,
    )

    return identity


def credentials_path(
    data_directory: Path,
) -> Path:
    return (
        data_directory
        / CREDENTIALS_FILENAME
    )


def has_credentials(
    data_directory: Path,
) -> bool:
    return credentials_path(
        data_directory,
    ).exists()


def save_credentials(
    data_directory: Path,
    *,
    device_id: str,
    agent_token: str,
    server_base_url: str,
) -> Path:
    if not device_id.strip():
        raise ValueError(
            "device_id không được rỗng"
        )

    if not agent_token.strip():
        raise ValueError(
            "agent_token không được rỗng"
        )

    path = credentials_path(
        data_directory,
    )

    payload = {
        "deviceId": device_id.strip(),
        "agentToken":
            agent_token.strip(),
        "serverBaseUrl":
            server_base_url.rstrip("/"),
        "enrolledAtUtc":
            utc_now_iso(),
    }

    _atomic_write_json(
        path,
        payload,
    )

    return path


def load_credentials(
    data_directory: Path,
) -> dict[str, str]:
    path = credentials_path(
        data_directory,
    )

    if not path.exists():
        raise FileNotFoundError(
            "Agent chưa được enrollment. "
            "Không tìm thấy "
            "data/credentials.json"
        )

    payload = json.loads(
        path.read_text(
            encoding="utf-8-sig",
        )
    )

    device_id = payload.get(
        "deviceId"
    )

    agent_token = payload.get(
        "agentToken"
    )

    if (
        not isinstance(device_id, str)
        or not device_id.strip()
    ):
        raise ValueError(
            "credentials.deviceId "
            "không hợp lệ"
        )

    if (
        not isinstance(agent_token, str)
        or not agent_token.strip()
    ):
        raise ValueError(
            "credentials.agentToken "
            "không hợp lệ"
        )

    result = {
        "deviceId": device_id.strip(),
        "agentToken":
            agent_token.strip(),
    }

    server_base_url = payload.get(
        "serverBaseUrl"
    )

    if (
        isinstance(
            server_base_url,
            str,
        )
        and server_base_url.strip()
    ):
        result["serverBaseUrl"] = (
            server_base_url
            .strip()
            .rstrip("/")
        )

    return result
