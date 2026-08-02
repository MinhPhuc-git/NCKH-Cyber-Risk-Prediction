from __future__ import annotations

from typing import Any

from .api_client import ApiClient
from .collectors.system import (
    get_device_info,
)
from .config import AppConfig
from .identity import (
    has_credentials,
    load_or_create_identity,
    save_credentials,
)


class EnrollmentError(RuntimeError):
    pass


def enroll_agent(
    config: AppConfig,
    api: ApiClient,
    enrollment_code: str,
) -> dict[str, str]:
    normalized_code = (
        enrollment_code
        .strip()
        .upper()
    )

    if not normalized_code:
        raise EnrollmentError(
            "Mã liên kết không được rỗng"
        )

    if has_credentials(
        config.agent.data_directory,
    ):
        raise EnrollmentError(
            "Agent đã có credentials.json. "
            "Thiết bị này đã được liên kết."
        )

    identity = load_or_create_identity(
        config.agent.data_directory,
    )

    device_info = get_device_info()

    hostname = str(
        device_info.get("hostname")
        or "UNKNOWN-WINDOWS-DEVICE"
    )[:255]

    operating_system = str(
        device_info.get("platform")
        or (
            f"{device_info.get('operatingSystem', '')} "
            f"{device_info.get('osVersion', '')}"
        ).strip()
        or "Windows"
    )[:255]

    architecture_value: Any = (
        device_info.get("architecture")
    )

    architecture = (
        str(architecture_value)[:50]
        if architecture_value
        else None
    )

    response = api.enroll(
        {
            "enrollmentCode":
                normalized_code,
            "installationId":
                identity[
                    "installationId"
                ],
            "hostname":
                hostname,
            "operatingSystem":
                operating_system,
            "architecture":
                architecture,
            "agentVersion":
                config.agent.version,
        }
    )

    if not isinstance(response, dict):
        raise EnrollmentError(
            "Phản hồi enrollment "
            "không hợp lệ"
        )

    device_id = response.get(
        "deviceId"
    )

    agent_token = response.get(
        "agentToken"
    )

    status = response.get(
        "status"
    )

    if (
        not isinstance(device_id, str)
        or not device_id.strip()
        or not isinstance(
            agent_token,
            str,
        )
        or not agent_token.strip()
    ):
        raise EnrollmentError(
            "Server không trả về "
            "deviceId hoặc agentToken "
            "hợp lệ"
        )

    credential_path = save_credentials(
        config.agent.data_directory,
        device_id=device_id,
        agent_token=agent_token,
        server_base_url=(
            config.server.base_url
        ),
    )

    return {
        "deviceId":
            device_id,
        "status":
            str(status or "IDLE"),
        "credentialsPath":
            str(credential_path),
    }


def enrollment_status(
    config: AppConfig,
) -> dict[str, Any]:
    identity = load_or_create_identity(
        config.agent.data_directory,
    )

    result: dict[str, Any] = {
        "installationId":
            identity["installationId"],
        "enrolled": False,
        "deviceId": None,
        "serverBaseUrl":
            config.server.base_url,
    }

    if not has_credentials(
        config.agent.data_directory,
    ):
        return result

    from .identity import (
        load_credentials,
    )

    credentials = load_credentials(
        config.agent.data_directory,
    )

    result.update(
        {
            "enrolled": True,
            "deviceId":
                credentials["deviceId"],
            "serverBaseUrl":
                credentials.get(
                    "serverBaseUrl",
                    config.server.base_url,
                ),
        }
    )

    return result
