from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.config import (
    AgentSettings,
    AppConfig,
    ServerSettings,
)
from src.enrollment import (
    EnrollmentError,
    enroll_agent,
)
from src.identity import (
    load_credentials,
)


class FakeApiClient:
    def enroll(
        self,
        payload: dict[str, object],
    ) -> dict[str, str]:
        self.payload = payload

        return {
            "deviceId":
                "77bb70b8-28bd-4afe-"
                "84eb-c8882ab5b3a9",
            "agentToken":
                "test-agent-token",
            "status":
                "IDLE",
        }


class EnrollmentTests(
    unittest.TestCase,
):
    def build_config(
        self,
        root: Path,
    ) -> AppConfig:
        return AppConfig(
            root_directory=root,
            source_path=(
                root / "config.json"
            ),
            agent=AgentSettings(
                version="0.1.0",
                schema_version="1.0",
                data_directory=(
                    root / "data"
                ),
                log_directory=(
                    root / "logs"
                ),
                system32_file_limit=5,
                system32_recursive=False,
                powershell_timeout_seconds=2,
                max_network_connections=10,
                monitored_ports=(445,),
            ),
            server=ServerSettings(
                base_url=(
                    "http://127.0.0.1:"
                    "3001/api/v1"
                ),
                request_timeout_seconds=2,
                poll_interval_seconds=1,
                long_poll_seconds=1,
            ),
        )

    @patch(
        "src.enrollment."
        "get_device_info"
    )
    def test_enrolls_and_saves_credentials(
        self,
        get_device_info_mock,
    ) -> None:
        get_device_info_mock.return_value = {
            "hostname":
                "DESKTOP-TEST",
            "platform":
                "Windows 11 Pro",
            "architecture":
                "AMD64",
        }

        with tempfile.TemporaryDirectory() as (
            temporary_directory
        ):
            root = Path(
                temporary_directory
            )

            config = self.build_config(
                root,
            )

            api = FakeApiClient()

            result = enroll_agent(
                config,
                api,
                "cyrp-a7k9-m2q4",
            )

            credentials = load_credentials(
                config
                .agent
                .data_directory
            )

            self.assertEqual(
                result["deviceId"],
                credentials["deviceId"],
            )

            self.assertEqual(
                credentials["agentToken"],
                "test-agent-token",
            )

            self.assertEqual(
                api.payload[
                    "enrollmentCode"
                ],
                "CYRP-A7K9-M2Q4",
            )

            self.assertNotIn(
                "agentToken",
                result,
            )

    @patch(
        "src.enrollment."
        "get_device_info"
    )
    def test_rejects_existing_credentials(
        self,
        get_device_info_mock,
    ) -> None:
        get_device_info_mock.return_value = {
            "hostname":
                "DESKTOP-TEST",
            "platform":
                "Windows 11 Pro",
            "architecture":
                "AMD64",
        }

        with tempfile.TemporaryDirectory() as (
            temporary_directory
        ):
            root = Path(
                temporary_directory
            )

            config = self.build_config(
                root,
            )

            data_directory = (
                config
                .agent
                .data_directory
            )

            data_directory.mkdir(
                parents=True,
            )

            (
                data_directory
                / "credentials.json"
            ).write_text(
                (
                    '{"deviceId":"existing",'
                    '"agentToken":"token"}'
                ),
                encoding="utf-8",
            )

            with self.assertRaises(
                EnrollmentError,
            ):
                enroll_agent(
                    config,
                    FakeApiClient(),
                    "CYRP-A7K9-M2Q4",
                )


if __name__ == "__main__":
    unittest.main()
