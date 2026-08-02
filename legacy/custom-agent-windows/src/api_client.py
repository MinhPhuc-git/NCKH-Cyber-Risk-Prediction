from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import ServerSettings


class ApiClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code


class ApiClient:
    def __init__(
        self,
        settings: ServerSettings,
    ) -> None:
        self.settings = settings

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> Any:
        normalized_path = (
            path
            if path.startswith("/")
            else f"/{path}"
        )

        url = (
            f"{self.settings.base_url}"
            f"{normalized_path}"
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": (
                "CYRP-Windows-Agent"
            ),
        }

        data: bytes | None = None

        if body is not None:
            headers["Content-Type"] = (
                "application/json"
            )
            data = json.dumps(
                body,
                ensure_ascii=False,
            ).encode("utf-8")

        if token:
            headers["Authorization"] = (
                f"Bearer {token}"
            )

        request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=(
                    timeout
                    or self.settings
                    .request_timeout_seconds
                ),
            ) as response:
                raw = (
                    response
                    .read()
                    .decode("utf-8")
                )

                return (
                    json.loads(raw)
                    if raw
                    else None
                )
        except urllib.error.HTTPError as error:
            raw = error.read().decode(
                "utf-8",
                errors="replace",
            )

            try:
                payload = (
                    json.loads(raw)
                    if raw
                    else {}
                )

                message = (
                    payload.get("message")
                    if isinstance(
                        payload,
                        dict,
                    )
                    else raw
                ) or raw
            except json.JSONDecodeError:
                message = raw

            if isinstance(message, list):
                message = ", ".join(
                    str(item)
                    for item in message
                )

            raise ApiClientError(
                str(
                    message
                    or f"HTTP {error.code}"
                ),
                status_code=error.code,
            ) from error
        except urllib.error.URLError as error:
            raise ApiClientError(
                "Không thể kết nối server: "
                f"{error.reason}"
            ) from error

    def health(self) -> Any:
        return self._request_json(
            "GET",
            "/health",
        )

    def enroll(
        self,
        payload: dict[str, Any],
    ) -> Any:
        return self._request_json(
            "POST",
            "/agents/enroll",
            body=payload,
        )

    def heartbeat(
        self,
        agent_token: str,
        device_id: str,
        state: str,
    ) -> Any:
        return self._request_json(
            "POST",
            "/agents/heartbeat",
            token=agent_token,
            body={
                "deviceId": device_id,
                "state": state,
            },
        )

    def poll_next_task(
        self,
        agent_token: str,
        device_id: str,
    ) -> Any:
        query = urllib.parse.urlencode(
            {
                "deviceId": device_id,
                "wait": (
                    self.settings
                    .long_poll_seconds
                ),
            }
        )

        return self._request_json(
            "GET",
            f"/agents/tasks/next?{query}",
            token=agent_token,
            timeout=(
                self.settings
                .long_poll_seconds + 5
            ),
        )

    def submit_scan_result(
        self,
        agent_token: str,
        scan_id: str,
        payload: dict[str, Any],
    ) -> Any:
        quoted_scan_id = urllib.parse.quote(
            scan_id,
        )

        return self._request_json(
            "POST",
            (
                "/agents/scans/"
                f"{quoted_scan_id}/result"
            ),
            token=agent_token,
            body=payload,
        )
