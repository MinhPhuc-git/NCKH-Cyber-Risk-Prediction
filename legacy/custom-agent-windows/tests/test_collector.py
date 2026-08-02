from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.collector import collect_agent_data
from src.config import load_config
from src.logging_config import (
    close_logger_handlers,
    configure_logging,
)


class CollectorTests(unittest.TestCase):
    def test_payload_has_required_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as (
            temporary_directory
        ):
            root = Path(temporary_directory)
            config_path = root / "config.json"

            config_path.write_text(
                json.dumps(
                    {
                        "agent": {
                            "version": "0.1.0",
                            "schemaVersion": "1.0",
                            "dataDirectory": str(
                                root / "data"
                            ),
                            "logDirectory": str(
                                root / "logs"
                            ),
                            "system32FileLimit": 5,
                            "system32Recursive": False,
                            "powershellTimeoutSeconds": 2,
                            "maxNetworkConnections": 10,
                            "monitoredPorts": [
                                445,
                                3389,
                            ],
                        },
                        "server": {
                            "baseUrl": (
                                "http://127.0.0.1:"
                                "3001/api/v1"
                            ),
                            "requestTimeoutSeconds": 2,
                            "pollIntervalSeconds": 1,
                            "longPollSeconds": 1,
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(config_path)

            logger = configure_logging(
                config.agent.log_directory,
                force_reconfigure=True,
            )

            try:
                payload = collect_agent_data(
                    config,
                    skip_system32=True,
                    logger=logger,
                )

                self.assertEqual(
                    payload["schemaVersion"],
                    "1.0",
                )
                self.assertEqual(
                    payload["agentVersion"],
                    "0.1.0",
                )
                self.assertIsInstance(
                    payload["scanId"],
                    str,
                )
                self.assertIn(
                    "agentInstallationId",
                    payload,
                )
                self.assertIn(
                    "data",
                    payload,
                )
                self.assertIn(
                    "deviceInfo",
                    payload["data"],
                )
                self.assertTrue(
                    payload["data"][
                        "system32Inventory"
                    ]["skipped"]
                )
            finally:
                close_logger_handlers(logger)


if __name__ == "__main__":
    unittest.main()
